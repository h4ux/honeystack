package honeypots

import (
	"context"
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

type HTTP struct {
	cfg    config.Service
	store  *eventlog.Store
	server *http.Server
	mu     sync.Mutex
}

func NewHTTP(cfg config.Service, store *eventlog.Store) *HTTP {
	return &HTTP{cfg: cfg, store: store}
}

func (h *HTTP) Name() string { return "http" }
func (h *HTTP) Port() int    { return h.cfg.Port }

func (h *HTTP) UpdateConfig(cfg config.Service) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cfg = cfg
}

func (h *HTTP) currentCfg() config.Service {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cfg
}

func (h *HTTP) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handle)
	h.server = &http.Server{Addr: ":" + strconv.Itoa(h.cfg.Port), Handler: mux}
	l, err := net.Listen("tcp", h.server.Addr)
	if err != nil {
		return err
	}
	go func() {
		if err := h.server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			h.store.Log(eventlog.Event{Service: "http", Type: "server_error", Details: map[string]any{"error": err.Error()}})
		}
	}()
	return nil
}

func (h *HTTP) Stop() error {
	if h.server != nil {
		return h.server.Close()
	}
	return nil
}

func (h *HTTP) handle(w http.ResponseWriter, r *http.Request) {
	cfg := h.currentCfg()
	remoteIP, remotePort := splitHostPort(r.RemoteAddr)
	sessionID := eventlog.RandID(6)

	body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	defer r.Body.Close()

	loginPath := cfg.LoginPagePath
	if loginPath == "" {
		loginPath = "/login"
	}
	isLogin := r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, loginPath)

	username, password := parseAuthBody(body, r.Header.Get("Content-Type"))
	eventType := "request"
	if isLogin && username != "" {
		eventType = "login_attempt"
	}
	h.store.Log(eventlog.Event{
		Service: "http", Type: eventType, SessionID: sessionID,
		RemoteIP: remoteIP, RemotePort: remotePort, LocalPort: cfg.Port,
		Username: username, Password: password,
		Command: r.Method + " " + r.URL.RequestURI(),
		Details: map[string]any{
			"method":  r.Method,
			"url":     r.URL.RequestURI(),
			"headers": flattenHeaders(r.Header),
			"body":    string(body),
		},
	})

	serverHeader := cfg.ServerHeader
	if serverHeader == "" {
		serverHeader = "Apache/2.4.52 (Ubuntu)"
	}
	w.Header().Set("Server", serverHeader)
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")

	switch {
	case r.URL.Path == "/" || r.URL.Path == "/index.html" || r.URL.Path == "/index.php":
		_, _ = io.WriteString(w, renderHome())
	case strings.HasPrefix(r.URL.Path, loginPath):
		if isLogin {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, renderLogin("Invalid credentials."))
		} else {
			_, _ = io.WriteString(w, renderLogin(""))
		}
	case r.URL.Path == "/robots.txt":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "User-agent: *\nDisallow: /admin\nDisallow: /wp-admin\n")
	case strings.Contains(r.URL.Path, "wp-login") ||
		strings.Contains(r.URL.Path, "wp-admin") ||
		strings.Contains(r.URL.Path, "administrator") ||
		strings.Contains(r.URL.Path, "phpmyadmin"):
		_, _ = io.WriteString(w, renderLogin(""))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "<!doctype html><title>404 Not Found</title><h1>Not Found</h1>")
	}
	_ = context.TODO
}

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ",")
	}
	return out
}

func parseAuthBody(body []byte, contentType string) (string, string) {
	if len(body) == 0 {
		return "", ""
	}
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "application/x-www-form-urlencoded") {
		params := map[string]string{}
		for _, pair := range strings.Split(string(body), "&") {
			eq := strings.Index(pair, "=")
			if eq < 0 {
				continue
			}
			k, _ := decodeForm(pair[:eq])
			v, _ := decodeForm(pair[eq+1:])
			params[k] = v
		}
		return firstNonEmpty(params["username"], params["user"], params["email"], params["login"]),
			firstNonEmpty(params["password"], params["pass"], params["passwd"])
	}
	return "", ""
}

func decodeForm(s string) (string, error) {
	s = strings.ReplaceAll(s, "+", " ")
	return urlDecode(s)
}

func urlDecode(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) {
			hi := hexVal(s[i+1])
			lo := hexVal(s[i+2])
			if hi < 0 || lo < 0 {
				b.WriteByte(c)
				continue
			}
			b.WriteByte(byte(hi<<4 | lo))
			i += 2
		} else {
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

func hexVal(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10
	case b >= 'A' && b <= 'F':
		return int(b-'A') + 10
	}
	return -1
}

func renderHome() string {
	return `<!doctype html><html><head><title>Welcome</title></head><body>
<h1>It works!</h1>
<p>This is the default welcome page used to test the correct operation of the Apache2 server after installation on Ubuntu systems.</p>
<p><a href="/login">Login</a></p>
</body></html>`
}

func renderLogin(err string) string {
	errBlock := ""
	if err != "" {
		errBlock = `<p style="color:red">` + err + `</p>`
	}
	return `<!doctype html><html><head><title>Login</title></head><body>
<h2>Sign in</h2>` + errBlock + `
<form method="POST" action="/login">
  <label>Username <input name="username" autofocus></label><br>
  <label>Password <input name="password" type="password"></label><br>
  <button type="submit">Log in</button>
</form>
</body></html>`
}
