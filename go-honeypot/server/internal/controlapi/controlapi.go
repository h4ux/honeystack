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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/manager"
)

type SyncFunc func(cfg config.Config)

type Server struct {
	store   *eventlog.Store
	manager *manager.Manager
	sync    SyncFunc

	authKey string
	http    *http.Server
	origins []string
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
		"version":  "1",
		"time":     time.Now().UnixMilli(),
		"config":   config.Get(),
		"services": s.manager.List(),
		"stats":    s.store.Stats(),
		"events":   s.store.Events(eventlog.EventFilter{Limit: 200}),
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
		var req struct {
			Service string `json:"service"`
			Limit   int    `json:"limit"`
		}
		if len(msg.Payload) > 0 {
			_ = json.Unmarshal(msg.Payload, &req)
		}
		reply(s.store.Sessions(req.Service, req.Limit))
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
