package controlapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) tokenFrom(r *http.Request) string {
	if t := r.URL.Query().Get("token"); t != "" {
		return t
	}
	if t := r.Header.Get("X-Auth-Key"); t != "" {
		return t
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := s.tokenFrom(r)
		if subtleCompare(token, s.authKey) {
			next(w, r)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
}

func subtleCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0 && a != ""
}

func (s *Server) restHello(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  "1",
		"config":   config.Get(),
		"services": s.manager.List(),
		"stats":    s.store.Stats(),
		"events":   s.store.Events(eventlog.EventFilter{Limit: 200}),
		"build":    s.buildInfo(),
		"geo":      s.geoStats(),
		"pubaddr":  s.publicAddr(),
	})
}

func (s *Server) restEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	until, _ := strconv.ParseInt(r.URL.Query().Get("until"), 10, 64)
	writeJSON(w, http.StatusOK, s.store.Events(eventlog.EventFilter{
		Service: r.URL.Query().Get("service"),
		Type:    r.URL.Query().Get("type"),
		IP:      r.URL.Query().Get("ip"),
		Search:  r.URL.Query().Get("q"),
		Since:   since,
		Until:   until,
		Limit:   limit,
	}))
}

func (s *Server) restRange(w http.ResponseWriter, r *http.Request) {
	oldest, newest := s.store.Range()
	writeJSON(w, http.StatusOK, map[string]any{"oldest": oldest, "newest": newest})
}

func (s *Server) restSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	minCmds, _ := strconv.Atoi(q.Get("minCommands"))
	since, _ := strconv.ParseInt(q.Get("since"), 10, 64)
	until, _ := strconv.ParseInt(q.Get("until"), 10, 64)
	req := sessionRequest{
		Service:     q.Get("service"),
		IP:          q.Get("ip"),
		Username:    q.Get("username"),
		CountryCode: q.Get("country"),
		Status:      q.Get("status"),
		MinCommands: minCmds,
		Since:       since,
		Until:       until,
		Search:      q.Get("q"),
		Sort:        q.Get("sort"),
		Limit:       limit,
	}
	writeJSON(w, http.StatusOK, s.store.Sessions(req.filter()))
}

// restGeo resolves a batch of IPs: /v1/geo?ips=1.2.3.4,5.6.7.8
func (s *Server) restGeo(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("ips")
	var ips []string
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			ips = append(ips, p)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"locations": s.geoBatch(ips),
		"geo":       s.geoStats(),
	})
}

func (s *Server) restVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.buildInfo())
}

// restPubAddr reports the tracked public address and its change history.
func (s *Server) restPubAddr(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.publicAddr())
}

func (s *Server) restSession(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	sess, ok := s.store.Session(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, sess)
}

func (s *Server) restStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.Stats())
}

func (s *Server) restServices(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.manager.List())
}

func (s *Server) restConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, config.Get())
	case http.MethodPut, http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		var newCfg config.Config
		if err := json.Unmarshal(body, &newCfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid config: " + err.Error()})
			return
		}
		if err := config.Set(newCfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		s.sync(config.Get())
		writeJSON(w, http.StatusOK, config.Get())
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
