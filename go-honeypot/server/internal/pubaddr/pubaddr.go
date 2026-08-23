// Package pubaddr keeps track of the host's public IP address and, when a
// dynamic-DNS credential is configured, keeps a hostname pointed at it.
//
// A honeypot on a residential or cheap-VPS connection can be renumbered at
// any time, which silently breaks every dashboard bookmark. This package
// polls the address on a timer, records every change to disk, mirrors the
// change into the event log, and pushes the new address to a DynDNS-style
// endpoint. The updater speaks the plain "GET with basic auth" protocol
// that xyz.frl, DuckDNS, No-IP and friends all accept, so the provider is
// a URL template rather than code.
package pubaddr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

// Change is one entry in the address history.
type Change struct {
	TS         int64  `json:"ts"`
	IP         string `json:"ip"`
	PreviousIP string `json:"previousIp,omitempty"`
	Source     string `json:"source,omitempty"` // which echo service answered
	Hostname   string `json:"hostname,omitempty"`
	// Update reports what the DynDNS provider said: ok, rate-limited,
	// unauthorized, disabled, or an error string.
	Update     string `json:"update,omitempty"`
	HTTPStatus int    `json:"httpStatus,omitempty"`
	// First marks the initial detection rather than an actual change.
	First bool `json:"first,omitempty"`
}

// Status is what the API and dashboard render.
type Status struct {
	Enabled      bool     `json:"enabled"`
	Provider     string   `json:"provider,omitempty"`
	Hostname     string   `json:"hostname,omitempty"`
	URL          string   `json:"url,omitempty"`
	IP           string   `json:"ip,omitempty"`
	Source       string   `json:"source,omitempty"`
	LastCheck    int64    `json:"lastCheck,omitempty"`
	LastChange   int64    `json:"lastChange,omitempty"`
	LastUpdate   int64    `json:"lastUpdate,omitempty"`
	UpdateStatus string   `json:"updateStatus,omitempty"`
	IntervalMin  int      `json:"intervalMinutes,omitempty"`
	Changes      int      `json:"changes"`
	History      []Change `json:"history,omitempty"`
}

// Credentials are stored separately from config.json, at 0600.
type Credentials struct {
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	Password string `json:"password"`
}

const (
	defaultIntervalMinutes = 5
	defaultMaxHistory      = 200
	// The providers we target rate-limit updates; never call more often.
	minUpdateInterval = 60 * time.Second
	httpTimeout       = 10 * time.Second
)

var defaultIPCheckURLs = []string{
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
	"https://icanhazip.com",
}

type Tracker struct {
	cfg   config.DynDNS
	creds Credentials
	store *eventlog.Store

	client *http.Client

	mu           sync.RWMutex
	ip           string
	source       string
	lastCheck    time.Time
	lastChange   time.Time
	lastUpdate   time.Time
	updateStatus string
	history      []Change

	closeOnce sync.Once
	closeCh   chan struct{}
	wg        sync.WaitGroup

	// onChange is called (outside the lock) whenever the address changes,
	// so main can refresh the systemd status line.
	onChange func(Status)
}

func New(cfg config.DynDNS, store *eventlog.Store) *Tracker {
	t := &Tracker{
		cfg:     cfg,
		store:   store,
		client:  &http.Client{Timeout: httpTimeout},
		closeCh: make(chan struct{}),
	}
	t.creds = loadCredentials(cfg)
	t.loadHistory()
	return t
}

// SetOnChange registers a callback fired after every recorded change.
func (t *Tracker) SetOnChange(fn func(Status)) {
	t.mu.Lock()
	t.onChange = fn
	t.mu.Unlock()
}

func (t *Tracker) Enabled() bool { return t.cfg.Enabled }

// Hostname is the name this host is reachable by, if one is configured.
func (t *Tracker) Hostname() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.hostnameLocked()
}

func (t *Tracker) hostnameLocked() string {
	if t.cfg.Hostname != "" {
		return t.cfg.Hostname
	}
	return t.creds.Hostname
}

// URL is the hostname as an https:// address, for printing.
func (t *Tracker) URL() string {
	host := t.Hostname()
	if host == "" {
		return ""
	}
	return "https://" + host
}

// Start begins polling. It runs one check immediately so the banner and the
// dashboard have an address without waiting for the first tick.
func (t *Tracker) Start(ctx context.Context) {
	if !t.cfg.Enabled {
		return
	}
	interval := time.Duration(t.intervalMinutes()) * time.Minute
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.checkOnce(ctx)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.closeCh:
				return
			case <-ticker.C:
				t.checkOnce(ctx)
			}
		}
	}()
}

func (t *Tracker) Close() {
	t.closeOnce.Do(func() {
		close(t.closeCh)
		t.wg.Wait()
		t.saveHistory()
	})
}

func (t *Tracker) intervalMinutes() int {
	if t.cfg.IntervalMinutes > 0 {
		return t.cfg.IntervalMinutes
	}
	return defaultIntervalMinutes
}

// checkOnce detects the current address, records a change if there is one,
// and pushes an update to the provider.
func (t *Tracker) checkOnce(ctx context.Context) {
	ip, source, err := t.detectIP(ctx)
	now := time.Now()

	t.mu.Lock()
	t.lastCheck = now
	previous := t.ip
	t.mu.Unlock()

	if err != nil {
		// Losing the network is normal on a flaky host; log it as an event
		// rather than a change, and try again on the next tick.
		t.store.Log(eventlog.Event{
			Service: "system", Type: "public_ip_error",
			Details: map[string]any{"error": err.Error()},
		})
		return
	}

	changed := ip != previous
	if changed {
		t.mu.Lock()
		t.ip, t.source, t.lastChange = ip, source, now
		t.mu.Unlock()
	}

	// Push to the provider: on every tick when configured, because a
	// stateless DynDNS record can expire if it is never refreshed.
	updateStatus, code := t.pushUpdate(ctx, ip, changed)

	t.mu.Lock()
	t.updateStatus = updateStatus
	if updateStatus == "ok" {
		t.lastUpdate = now
	}
	t.mu.Unlock()

	if !changed {
		return
	}

	entry := Change{
		TS: now.UnixMilli(), IP: ip, PreviousIP: previous, Source: source,
		Hostname: t.Hostname(), Update: updateStatus, HTTPStatus: code,
		First: previous == "",
	}
	t.recordChange(entry)
}

// recordChange appends to the history, persists it, logs an event and fires
// the callback.
func (t *Tracker) recordChange(c Change) {
	t.mu.Lock()
	t.history = append(t.history, c)
	max := t.cfg.MaxHistory
	if max <= 0 {
		max = defaultMaxHistory
	}
	if len(t.history) > max {
		t.history = t.history[len(t.history)-max:]
	}
	cb := t.onChange
	t.mu.Unlock()

	t.saveHistory()

	details := map[string]any{
		"ip": c.IP, "source": c.Source, "update": c.Update,
	}
	if c.PreviousIP != "" {
		details["previousIp"] = c.PreviousIP
	}
	if c.Hostname != "" {
		details["hostname"] = c.Hostname
	}
	typ := "public_ip_changed"
	msg := fmt.Sprintf("public IP changed: %s -> %s", c.PreviousIP, c.IP)
	if c.First {
		typ = "public_ip"
		msg = "public IP detected: " + c.IP
	}
	if host := c.Hostname; host != "" {
		msg += " (https://" + host + ")"
	}
	t.store.Log(eventlog.Event{
		Service: "system", Type: typ, Command: msg, Details: details,
	})
	log.Printf("[pubaddr] %s [update: %s]", msg, c.Update)

	if cb != nil {
		cb(t.Status())
	}
}

// detectIP asks each echo service in turn and returns the first valid
// answer, along with which service gave it.
func (t *Tracker) detectIP(ctx context.Context) (string, string, error) {
	urls := t.cfg.IPCheckURLs
	if len(urls) == 0 {
		urls = defaultIPCheckURLs
	}
	var lastErr error
	for _, u := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "honeystack-pubaddr/1")
		resp, err := t.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
			continue
		}
		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) == nil {
			lastErr = fmt.Errorf("%s: %q is not an IP", u, truncate(ip, 40))
			continue
		}
		return ip, hostOf(u), nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no ip check urls configured")
	}
	return "", "", lastErr
}

// pushUpdate sends the address to the DynDNS provider. It returns a short
// status string and the HTTP code, and never blocks longer than the client
// timeout.
func (t *Tracker) pushUpdate(ctx context.Context, ip string, changed bool) (string, int) {
	url := t.updateURL(ip)
	if url == "" {
		return "no-provider", 0
	}
	t.mu.RLock()
	last := t.lastUpdate
	user, pass := t.username(), t.password()
	t.mu.RUnlock()

	// Providers rate-limit; skip a refresh that is too soon unless the
	// address actually changed (in which case try anyway and report 429).
	if !changed && !last.IsZero() && time.Since(last) < minUpdateInterval {
		return "skipped", 0
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "error: " + err.Error(), 0
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	req.Header.Set("User-Agent", "honeystack-pubaddr/1")
	resp, err := t.client.Do(req)
	if err != nil {
		return "error: " + err.Error(), 0
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	text := strings.TrimSpace(string(body))

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return "rate-limited", resp.StatusCode
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return "unauthorized", resp.StatusCode
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// The DynDNS convention is a "good"/"nochg" body; xyz.frl answers
		// 202 with an empty body. Both count as accepted.
		if strings.HasPrefix(text, "nochg") {
			return "nochg", resp.StatusCode
		}
		if text != "" && !strings.HasPrefix(text, "good") {
			return "ok: " + truncate(text, 60), resp.StatusCode
		}
		return "ok", resp.StatusCode
	default:
		return fmt.Sprintf("error: HTTP %d %s", resp.StatusCode, truncate(text, 60)), resp.StatusCode
	}
}

// updateURL builds the provider request for this address.
func (t *Tracker) updateURL(ip string) string {
	tmpl := t.cfg.UpdateURL
	if tmpl == "" {
		switch strings.ToLower(t.cfg.Provider) {
		case "", "xyz.frl", "xyzfrl":
			tmpl = "https://xyz.frl/nic/update?myip={ip}"
		case "duckdns":
			tmpl = "https://www.duckdns.org/update?domains={hostname}&token={password}&ip={ip}"
		case "noip", "no-ip":
			tmpl = "https://dynupdate.no-ip.com/nic/update?hostname={hostname}&myip={ip}"
		case "dyndns", "custom":
			return "" // a custom provider must supply updateUrl
		default:
			tmpl = "https://" + strings.TrimSuffix(t.cfg.Provider, "/") + "/nic/update?myip={ip}"
		}
	}
	host := t.Hostname()
	if strings.Contains(tmpl, "{hostname}") && host == "" {
		return ""
	}
	if t.username() == "" && t.password() == "" && strings.Contains(tmpl, "{password}") {
		return ""
	}
	r := strings.NewReplacer(
		"{ip}", ip,
		"{hostname}", host,
		"{username}", t.username(),
		"{password}", t.password(),
	)
	return r.Replace(tmpl)
}

func (t *Tracker) username() string {
	if t.cfg.Username != "" {
		return t.cfg.Username
	}
	return t.creds.Username
}

func (t *Tracker) password() string {
	if t.cfg.Password != "" {
		return t.cfg.Password
	}
	return t.creds.Password
}

// Status snapshots the tracker for the API.
func (t *Tracker) Status() Status {
	t.mu.RLock()
	defer t.mu.RUnlock()
	st := Status{
		Enabled:      t.cfg.Enabled,
		Provider:     t.cfg.Provider,
		Hostname:     t.hostnameLocked(),
		IP:           t.ip,
		Source:       t.source,
		UpdateStatus: t.updateStatus,
		IntervalMin:  t.intervalMinutes(),
		Changes:      len(t.history),
	}
	if st.Hostname != "" {
		st.URL = "https://" + st.Hostname
	}
	if !t.lastCheck.IsZero() {
		st.LastCheck = t.lastCheck.UnixMilli()
	}
	if !t.lastChange.IsZero() {
		st.LastChange = t.lastChange.UnixMilli()
	}
	if !t.lastUpdate.IsZero() {
		st.LastUpdate = t.lastUpdate.UnixMilli()
	}
	// Newest first: the dashboard renders it as a log.
	st.History = make([]Change, 0, len(t.history))
	for i := len(t.history) - 1; i >= 0; i-- {
		st.History = append(st.History, t.history[i])
	}
	return st
}

// ---- persistence ----

func (t *Tracker) historyPath() string {
	if t.cfg.HistoryFile != "" {
		return t.cfg.HistoryFile
	}
	return "data/ip-history.json"
}

func (t *Tracker) loadHistory() {
	data, err := os.ReadFile(t.historyPath())
	if err != nil {
		return
	}
	var hist []Change
	if err := json.Unmarshal(data, &hist); err != nil {
		return
	}
	t.mu.Lock()
	t.history = hist
	if n := len(hist); n > 0 {
		// Resume from the last known address so a restart does not record a
		// spurious "changed" entry.
		t.ip = hist[n-1].IP
		t.source = hist[n-1].Source
		t.lastChange = time.UnixMilli(hist[n-1].TS)
	}
	t.mu.Unlock()
}

func (t *Tracker) saveHistory() {
	t.mu.RLock()
	snapshot := make([]Change, len(t.history))
	copy(snapshot, t.history)
	t.mu.RUnlock()

	path := t.historyPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
	}
}

// loadCredentials reads the 0600 credentials file written at install time.
func loadCredentials(cfg config.DynDNS) Credentials {
	path := cfg.CredentialsFile
	if path == "" {
		path = "data/dyndns.json"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Credentials{}
	}
	var c Credentials
	if err := json.Unmarshal(data, &c); err != nil {
		log.Printf("[pubaddr] %s is not valid JSON: %v", path, err)
		return Credentials{}
	}
	return c
}

// SaveCredentials writes the credential file with owner-only permissions.
func SaveCredentials(path string, c Credentials) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func hostOf(u string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexAny(s, "/?"); i > 0 {
		s = s[:i]
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
