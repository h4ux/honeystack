// Package controlapi exposes a WebSocket-based control API that a remote
// webapp can connect to using host:port + a per-run auth key. All
// mutations to config are wired through the same manager that owns the
// running services.
package controlapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/blocklist"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/geoip"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/manager"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/pubaddr"
)

type SyncFunc func(cfg config.Config)

// BuildInfo is what the daemon knows about itself. The dashboard compares
// Commit against the latest GitHub release to offer an update.
type BuildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	GoVersion string `json:"goVersion"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	StartedAt int64  `json:"startedAt"`
	Repo      string `json:"repo,omitempty"`
	Binary    string `json:"binary,omitempty"`
	Services  int    `json:"services"`

	// Runtime footprint, so an operator can see what the daemon costs
	// without shelling into the box.
	HeapMB      float64 `json:"heapMb"`
	SysMB       float64 `json:"sysMb"`
	Goroutines  int     `json:"goroutines"`
	NumCPU      int     `json:"numCpu"`
	MemLimitMB  float64 `json:"memLimitMb,omitempty"`
	MaxLogRows  int     `json:"maxLogRows,omitempty"`
	MaxSessions int     `json:"maxSessions,omitempty"`
}

type Server struct {
	store     *eventlog.Store
	manager   *manager.Manager
	sync      SyncFunc
	geo       GeoLookup
	pubaddr   PublicAddr
	blocklist Blocklist
	build     BuildInfo

	authKey string
	http    *http.Server
	origins []string
}

// PublicAddr is the subset of internal/pubaddr the API needs.
type PublicAddr interface {
	Status() pubaddr.Status
}

// SetPublicAddr exposes public-IP tracking over the API.
func (s *Server) SetPublicAddr(p PublicAddr) { s.pubaddr = p }

func (s *Server) publicAddr() any {
	if s.pubaddr == nil {
		return map[string]any{"enabled": false}
	}
	return s.pubaddr.Status()
}

// Blocklist is the subset of internal/blocklist the API needs.
type Blocklist interface {
	Entries() []blocklist.Entry
	Add(value, reason, by string) (blocklist.Entry, error)
	Remove(value string) bool
	Len() int
}

// SetBlocklist exposes address blocking over the API.
func (s *Server) SetBlocklist(b Blocklist) { s.blocklist = b }

func (s *Server) blockEntries() any {
	if s.blocklist == nil {
		return map[string]any{"enabled": false, "entries": []any{}}
	}
	return map[string]any{"enabled": true, "entries": s.blocklist.Entries()}
}

// blockAdd blocks an address and records the action as an event, so the
// change is visible in the feed and the history like anything else.
func (s *Server) blockAdd(value, reason, by string) (any, error) {
	if s.blocklist == nil {
		return nil, errors.New("blocklist unavailable")
	}
	entry, err := s.blocklist.Add(value, reason, by)
	if err != nil {
		return nil, err
	}
	s.store.Log(eventlog.Event{
		Service: "system", Type: "ip_blocked",
		Command: "blocked " + entry.Value,
		Details: map[string]any{"value": entry.Value, "reason": entry.Reason, "by": by},
	})
	return s.blockEntries(), nil
}

func (s *Server) blockRemove(value, by string) (any, error) {
	if s.blocklist == nil {
		return nil, errors.New("blocklist unavailable")
	}
	if !s.blocklist.Remove(value) {
		return nil, fmt.Errorf("%s is not blocked", value)
	}
	s.store.Log(eventlog.Event{
		Service: "system", Type: "ip_unblocked",
		Command: "unblocked " + value,
		Details: map[string]any{"value": value, "by": by},
	})
	return s.blockEntries(), nil
}

// GeoLookup is the subset of internal/geoip the API needs.
type GeoLookup interface {
	Batch(ips []string) map[string]geoip.Location
	Stats() geoip.Stats
}

// SetGeo makes country data available over the API.
func (s *Server) SetGeo(g GeoLookup) { s.geo = g }

// SetBuildInfo records what this binary is, for the version check.
func (s *Server) SetBuildInfo(info BuildInfo) { s.build = info }

func (s *Server) buildInfo() BuildInfo {
	info := s.build
	info.Services = len(s.manager.List())

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	info.HeapMB = float64(m.HeapAlloc) / 1024 / 1024
	info.SysMB = float64(m.Sys) / 1024 / 1024
	info.Goroutines = runtime.NumGoroutine()
	info.NumCPU = runtime.NumCPU()
	// GOMEMLIMIT, when the operator set one.
	if limit := debug.SetMemoryLimit(-1); limit > 0 && limit != math.MaxInt64 {
		info.MemLimitMB = float64(limit) / 1024 / 1024
	}
	cfg := config.Get()
	info.MaxLogRows = cfg.Storage.MaxLogRows
	info.MaxSessions = cfg.Storage.MaxSessions
	return info
}

type Message struct {
	Type    string          `json:"type"`
	ReqID   string          `json:"reqId,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

func New(store *eventlog.Store, mgr *manager.Manager, sync SyncFunc) *Server {
	return &Server{store: store, manager: mgr, sync: sync}
}

// GenerateAuthKey creates a new random hex key, writes it to disk, and returns it.
func GenerateAuthKey(path string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	key := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		return "", err
	}
	return key, nil
}

func (s *Server) Start(ctx context.Context, cfg config.Control, authKey string) error {
	s.authKey = authKey
	s.origins = cfg.AllowedOrigins

	mux := http.NewServeMux()
	mux.HandleFunc("/api", s.handleWS)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("/v1/hello", s.withAuth(s.restHello))
	mux.HandleFunc("/v1/events", s.withAuth(s.restEvents))
	mux.HandleFunc("/v1/range", s.withAuth(s.restRange))
	mux.HandleFunc("/v1/sessions", s.withAuth(s.restSessions))
	mux.HandleFunc("/v1/session", s.withAuth(s.restSession))
	mux.HandleFunc("/v1/stats", s.withAuth(s.restStats))
	mux.HandleFunc("/v1/services", s.withAuth(s.restServices))
	mux.HandleFunc("/v1/config", s.withAuth(s.restConfig))
	mux.HandleFunc("/v1/geo", s.withAuth(s.restGeo))
	mux.HandleFunc("/v1/version", s.withAuth(s.restVersion))
	mux.HandleFunc("/v1/pubaddr", s.withAuth(s.restPubAddr))
	mux.HandleFunc("/v1/blocklist", s.withAuth(s.restBlocklist))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("honeypot control-plane is up.\nWebSocket: ws://" + r.Host + "/api?token=<AUTH_KEY>\nREST: /v1/* with Authorization: Bearer <AUTH_KEY>\n"))
	})

	addr := cfg.Host
	if addr == "" {
		addr = "0.0.0.0"
	}
	addr = net.JoinHostPort(addr, strconv.Itoa(cfg.Port))

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.http = &http.Server{
		Handler:           corsMiddleware(mux, s.origins),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		var err error
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			log.Printf("[controlapi] TLS listening on %s", addr)
			err = s.http.ServeTLS(l, cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			log.Printf("[controlapi] listening on %s", addr)
			err = s.http.Serve(l)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[controlapi] serve error: %v", err)
		}
	}()
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s.http == nil {
		return nil
	}
	return s.http.Shutdown(ctx)
}

// ------- WebSocket handling -------

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return true // origin is validated after upgrade via auth token
	},
}

type client struct {
	conn      *websocket.Conn
	sendMu    sync.Mutex
	closeOnce sync.Once
	done      chan struct{}
}

func (c *client) send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return c.conn.WriteMessage(websocket.TextMessage, b)
}

func (c *client) close() {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.conn.Close()
	})
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.authKey)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c := &client{conn: conn, done: make(chan struct{})}
	defer c.close()

	remote := conn.RemoteAddr().String()
	log.Printf("[controlapi] client connected from %s", remote)
	defer log.Printf("[controlapi] client disconnected from %s", remote)

	unsub := s.store.Subscribe(func(e eventlog.Event) {
		select {
		case <-c.done:
			return
		default:
		}
		_ = c.send(Message{Type: "event", Payload: mustJSON(e)})
	})
	defer unsub()

	// Send initial payload: config, services, stats, recent events
	if err := c.send(Message{Type: "hello", Payload: mustJSON(map[string]any{
		"version":   "1",
		"time":      time.Now().UnixMilli(),
		"config":    config.Get(),
		"services":  s.manager.List(),
		"stats":     s.store.Stats(),
		"events":    s.store.Events(eventlog.EventFilter{Limit: 200}),
		"build":     s.buildInfo(),
		"geo":       s.geoStats(),
		"pubaddr":   s.publicAddr(),
		"blocklist": s.blockEntries(),
	})}); err != nil {
		return
	}

	pingTicker := time.NewTicker(20 * time.Second)
	defer pingTicker.Stop()
	go func() {
		for {
			select {
			case <-c.done:
				return
			case <-pingTicker.C:
				c.sendMu.Lock()
				_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_ = c.conn.WriteMessage(websocket.PingMessage, nil)
				c.sendMu.Unlock()
			}
		}
	}()

	conn.SetReadLimit(1 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	})

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			_ = c.send(Message{Type: "error", Error: "invalid json: " + err.Error()})
			continue
		}
		s.handleCommand(c, msg)
	}
}

func (s *Server) handleCommand(c *client, msg Message) {
	reply := func(payload any) {
		_ = c.send(Message{Type: msg.Type + ":reply", ReqID: msg.ReqID, Payload: mustJSON(payload)})
	}
	fail := func(err error) { _ = c.send(Message{Type: msg.Type + ":reply", ReqID: msg.ReqID, Error: err.Error()}) }

	switch msg.Type {
	case "get_config":
		reply(config.Get())
	case "update_config":
		var newCfg config.Config
		if err := json.Unmarshal(msg.Payload, &newCfg); err != nil {
			fail(fmt.Errorf("invalid config: %w", err))
			return
		}
		if err := config.Set(newCfg); err != nil {
			fail(err)
			return
		}
		s.sync(config.Get())
		reply(config.Get())
	case "list_services":
		reply(s.manager.List())
	case "get_stats":
		reply(s.store.Stats())
	case "get_events":
		var filter eventlog.EventFilter
		if len(msg.Payload) > 0 {
			_ = json.Unmarshal(msg.Payload, &filter)
		}
		reply(s.store.Events(filter))
	case "get_sessions":
		var req sessionRequest
		if len(msg.Payload) > 0 {
			_ = json.Unmarshal(msg.Payload, &req)
		}
		reply(s.store.Sessions(req.filter()))
	case "get_session":
		var req struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(msg.Payload, &req); err != nil {
			fail(err)
			return
		}
		sess, ok := s.store.Session(req.ID)
		if !ok {
			fail(errors.New("not found"))
			return
		}
		reply(sess)
	case "get_range":
		oldest, newest := s.store.Range()
		reply(map[string]any{"oldest": oldest, "newest": newest})
	case "geo_lookup":
		var req struct {
			IPs []string `json:"ips"`
		}
		if len(msg.Payload) > 0 {
			_ = json.Unmarshal(msg.Payload, &req)
		}
		reply(map[string]any{"locations": s.geoBatch(req.IPs), "geo": s.geoStats()})
	case "get_version":
		reply(s.buildInfo())
	case "get_pubaddr":
		reply(s.publicAddr())
	case "get_blocklist":
		reply(s.blockEntries())
	case "block_ip":
		var req struct {
			Value  string `json:"value"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(msg.Payload, &req); err != nil {
			fail(err)
			return
		}
		out, err := s.blockAdd(req.Value, req.Reason, "dashboard")
		if err != nil {
			fail(err)
			return
		}
		reply(out)
	case "unblock_ip":
		var req struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(msg.Payload, &req); err != nil {
			fail(err)
			return
		}
		out, err := s.blockRemove(req.Value, "dashboard")
		if err != nil {
			fail(err)
			return
		}
		reply(out)
	case "ping":
		reply(map[string]any{"pong": time.Now().UnixMilli()})
	default:
		fail(fmt.Errorf("unknown message type: %s", msg.Type))
	}
}

// ------- helpers -------

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`null`)
	}
	return b
}

func corsMiddleware(next http.Handler, allowed []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allow := ""
		for _, a := range allowed {
			if a == "*" || strings.EqualFold(a, origin) {
				allow = a
				if a == "*" {
					allow = "*"
				} else {
					allow = origin
				}
				break
			}
		}
		if allow != "" {
			w.Header().Set("Access-Control-Allow-Origin", allow)
			w.Header().Set("Access-Control-Allow-Headers", "content-type,authorization,x-auth-key")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,OPTIONS")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// sessionRequest is the wire shape of the session filter, shared by the
// WebSocket action and the REST endpoint.
type sessionRequest struct {
	Service     string `json:"service"`
	IP          string `json:"ip"`
	Username    string `json:"username"`
	CountryCode string `json:"country"`
	Status      string `json:"status"`
	MinCommands int    `json:"minCommands"`
	Since       int64  `json:"since"`
	Until       int64  `json:"until"`
	Search      string `json:"q"`
	Sort        string `json:"sort"`
	Limit       int    `json:"limit"`
}

func (r sessionRequest) filter() eventlog.SessionFilter {
	limit := r.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 5000 {
		limit = 5000
	}
	return eventlog.SessionFilter{
		Service:     r.Service,
		IP:          r.IP,
		Username:    r.Username,
		CountryCode: r.CountryCode,
		Status:      r.Status,
		MinCommands: r.MinCommands,
		Since:       r.Since,
		Until:       r.Until,
		Search:      r.Search,
		Sort:        r.Sort,
		Limit:       limit,
	}
}

func (s *Server) geoBatch(ips []string) map[string]geoip.Location {
	if s.geo == nil || len(ips) == 0 {
		return map[string]geoip.Location{}
	}
	if len(ips) > 2000 {
		ips = ips[:2000]
	}
	return s.geo.Batch(ips)
}

func (s *Server) geoStats() any {
	if s.geo == nil {
		return map[string]any{"enabled": false}
	}
	return s.geo.Stats()
}
