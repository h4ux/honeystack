package honeypots

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/example/honeypot/internal/config"
	"github.com/example/honeypot/internal/eventlog"
)

// WebAPI is shared by HTTP-speaking infrastructure honeypots. It keeps each
// service protocol-aware while avoiding another copy of listener lifecycle.
type WebAPI struct {
	name   string
	cfg    config.Service
	store  *eventlog.Store
	server *http.Server
	mu     sync.RWMutex
	handle func(*WebAPI, http.ResponseWriter, *http.Request, []byte, ConnMeta, string)
}

func newWebAPI(name string, cfg config.Service, store *eventlog.Store,
	handle func(*WebAPI, http.ResponseWriter, *http.Request, []byte, ConnMeta, string)) *WebAPI {
	return &WebAPI{name: name, cfg: cfg, store: store, handle: handle}
}

func (h *WebAPI) Name() string { return h.name }
func (h *WebAPI) Port() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cfg.Port
}
func (h *WebAPI) UpdateConfig(cfg config.Service) {
	h.mu.Lock()
	h.cfg = cfg
	h.mu.Unlock()
}
func (h *WebAPI) currentCfg() config.Service {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cfg
}
func (h *WebAPI) Start() error {
	cfg := h.currentCfg()
	h.server = &http.Server{
		Addr:              ":" + strconv.Itoa(cfg.Port),
		ReadHeaderTimeout: 8_000_000_000,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 256*1024))
			_ = r.Body.Close()
			ip, remotePort := splitHostPort(r.RemoteAddr)
			meta := ConnMeta{RemoteIP: ip, RemotePort: remotePort, LocalPort: h.Port()}
			h.handle(h, w, r, body, meta, eventlog.RandID(6))
		}),
	}
	l, err := net.Listen("tcp", h.server.Addr)
	if err != nil {
		return err
	}
	go func() {
		if err := h.server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			h.store.Log(eventlog.Event{Service: h.name, Type: "server_error", Details: map[string]any{"error": err.Error()}})
		}
	}()
	return nil
}
func (h *WebAPI) Stop() error {
	if h.server != nil {
		return h.server.Close()
	}
	return nil
}

func NewClickHouseHTTP(cfg config.Service, store *eventlog.Store) *WebAPI {
	return newWebAPI("clickhouse", cfg, store, handleClickHouseHTTP)
}

func handleClickHouseHTTP(h *WebAPI, w http.ResponseWriter, r *http.Request, body []byte, meta ConnMeta, sessionID string) {
	cfg := h.currentCfg()
	user, password := basicCredentials(r)
	if v := r.Header.Get("X-ClickHouse-User"); v != "" {
		user = v
	}
	if v := r.Header.Get("X-ClickHouse-Key"); v != "" {
		password = v
	}
	query := r.URL.Query().Get("query")
	if query == "" {
		query = strings.TrimSpace(string(body))
	}
	typ := "request"
	if query != "" {
		typ = "query"
	}
	if user != "" || password != "" {
		typ = "login_attempt"
	}
	h.store.Log(eventlog.Event{
		Service: h.name, Type: typ, SessionID: sessionID,
		RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
		Username: user, Password: password, Command: query,
		Details: map[string]any{
			"method": r.Method, "url": r.URL.RequestURI(),
			"database": r.URL.Query().Get("database"), "headers": flattenHeaders(r.Header),
		},
	})

	version := firstNonEmpty(cfg.ServerVersion, "24.8.4.13")
	w.Header().Set("X-ClickHouse-Summary", `{"read_rows":"1","read_bytes":"1","written_rows":"0","written_bytes":"0","total_rows_to_read":"0"}`)
	w.Header().Set("X-ClickHouse-Server-Display-Name", "clickhouse-prod-01")
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	lower := strings.ToLower(strings.TrimSpace(query))
	switch {
	case query == "" && r.URL.Path == "/ping":
		_, _ = io.WriteString(w, "Ok.\n")
	case query == "" && r.URL.Path == "/":
		_, _ = io.WriteString(w, "Ok.\n")
	case strings.Contains(lower, "version()"):
		_, _ = io.WriteString(w, version+"\n")
	case strings.HasPrefix(lower, "select 1"):
		_, _ = io.WriteString(w, "1\n")
	case user != "" || password != "":
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "Code: 516. DB::Exception: Authentication failed: password is incorrect, or there is no user with such name. (AUTHENTICATION_FAILED)\n")
	default:
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "Code: 60. DB::Exception: Table default.events does not exist. (UNKNOWN_TABLE)\n")
	}
}

func NewElasticsearch(cfg config.Service, store *eventlog.Store) *WebAPI {
	return newWebAPI("elasticsearch", cfg, store, handleElasticsearch)
}

func handleElasticsearch(h *WebAPI, w http.ResponseWriter, r *http.Request, body []byte, meta ConnMeta, sessionID string) {
	cfg := h.currentCfg()
	user, password := basicCredentials(r)
	typ := "request"
	if len(body) > 0 || strings.Contains(r.URL.Path, "_search") || strings.Contains(r.URL.Path, "_bulk") {
		typ = "query"
	}
	if user != "" || password != "" {
		typ = "login_attempt"
	}
	h.store.Log(eventlog.Event{
		Service: h.name, Type: typ, SessionID: sessionID,
		RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
		Username: user, Password: password, Command: r.Method + " " + r.URL.RequestURI(),
		Details: map[string]any{"body": string(body), "headers": flattenHeaders(r.Header)},
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Elastic-Product", "Elasticsearch")
	version := firstNonEmpty(cfg.ServerVersion, "8.15.1")
	switch {
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		writeJSON(w, map[string]any{
			"name": "es-prod-01", "cluster_name": "production",
			"cluster_uuid": "honeyP0tCluster000001",
			"version":      map[string]any{"number": version, "build_flavor": "default", "build_type": "tar", "lucene_version": "9.11.1"},
			"tagline":      "You Know, for Search",
		})
	case strings.Contains(r.URL.Path, "_cluster/health"):
		writeJSON(w, map[string]any{"cluster_name": "production", "status": "yellow", "number_of_nodes": 3, "active_primary_shards": 12})
	case strings.Contains(r.URL.Path, "_cat"):
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "yellow open logs-2026.08.21 honey0001 1 1 128442 0 88.2mb 88.2mb\n")
	case user != "" || password != "":
		w.Header().Set("WWW-Authenticate", `Basic realm="security" charset="UTF-8"`)
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]any{"error": map[string]any{"type": "security_exception", "reason": "unable to authenticate user [" + user + "]"}, "status": 401})
	default:
		writeJSON(w, map[string]any{"took": 3, "timed_out": false, "hits": map[string]any{"total": map[string]any{"value": 0, "relation": "eq"}, "hits": []any{}}})
	}
}

func NewDocker(cfg config.Service, store *eventlog.Store) *WebAPI {
	return newWebAPI("docker", cfg, store, handleDocker)
}

func handleDocker(h *WebAPI, w http.ResponseWriter, r *http.Request, body []byte, meta ConnMeta, sessionID string) {
	cfg := h.currentCfg()
	user, password := basicCredentials(r)
	typ := "request"
	if user != "" || password != "" {
		typ = "login_attempt"
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		typ = "command"
	}
	h.store.Log(eventlog.Event{
		Service: h.name, Type: typ, SessionID: sessionID,
		RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
		Username: user, Password: password, Command: r.Method + " " + r.URL.RequestURI(),
		Details: map[string]any{"body": string(body), "headers": flattenHeaders(r.Header)},
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "Docker/"+firstNonEmpty(cfg.ServerVersion, "27.2.1")+" (linux)")
	p := stripDockerVersion(r.URL.Path)
	switch {
	case p == "/_ping":
		w.Header().Set("API-Version", "1.47")
		w.Header().Set("Docker-Experimental", "false")
		w.Header().Set("Ostype", "linux")
		_, _ = io.WriteString(w, "OK")
	case p == "/version":
		writeJSON(w, map[string]any{"Version": firstNonEmpty(cfg.ServerVersion, "27.2.1"), "ApiVersion": "1.47", "MinAPIVersion": "1.24", "GitCommit": "9e34c9b", "GoVersion": "go1.22.7", "Os": "linux", "Arch": "amd64"})
	case p == "/info":
		writeJSON(w, map[string]any{"ID": "HONEY:DOCKER:PROD:01", "Containers": 7, "ContainersRunning": 5, "Images": 18, "Name": "docker-prod-01", "ServerVersion": firstNonEmpty(cfg.ServerVersion, "27.2.1")})
	case p == "/containers/json":
		writeJSON(w, []any{
			map[string]any{"Id": "5c48b01280d7", "Names": []string{"/api-prod"}, "Image": "company/api:latest", "State": "running", "Status": "Up 12 days"},
			map[string]any{"Id": "19aa873b121e", "Names": []string{"/postgres"}, "Image": "postgres:16", "State": "running", "Status": "Up 12 days"},
		})
	case p == "/containers/create" && r.Method == http.MethodPost:
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"Id": "8d94c23b0cc47b7a9a030b70539f730eb45e82a8b9baeb7ea5e7b34c1fa2e71d", "Warnings": []any{}})
	case strings.HasPrefix(p, "/containers/") && (strings.HasSuffix(p, "/start") || strings.HasSuffix(p, "/stop")):
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]any{"message": "page not found"})
	}
}

func basicCredentials(r *http.Request) (string, string) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(auth), "basic ") {
		return "", ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[6:]))
	if err != nil {
		return "", ""
	}
	user, password, ok := strings.Cut(string(raw), ":")
	if !ok {
		return string(raw), ""
	}
	return user, password
}

func stripDockerVersion(p string) string {
	if !strings.HasPrefix(p, "/v") {
		return p
	}
	rest := p[2:]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[i:]
	}
	return p
}

func writeJSON(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v)
}
