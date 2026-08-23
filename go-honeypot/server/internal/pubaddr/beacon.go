package pubaddr

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
)

// The beacon: a small document at a fixed URL that always says where this
// host currently is.
//
// Dynamic DNS solves this by moving a name; that needs either an account or
// a domain you own, and a provider that actually publishes. A beacon needs
// neither. The daemon publishes {ip, port, …} to a fixed URL whenever the
// address changes, and the dashboard reads that URL to find the box again —
// so a bookmark of the *beacon* never goes stale even though the address
// does.
//
// Default backend is ntfy.sh: no signup, a topic is just a random string,
// and it answers browsers with `access-control-allow-origin: *`, which is
// what lets the static dashboard read it directly.
//
// Anyone who knows the topic can also publish to it, so the document is
// signed. The verify key lives in the URL fragment the operator keeps
// (fragments are never sent to the server), and the dashboard refuses a
// document whose signature does not match. Without that, a spoofed beacon
// could point the dashboard — and the auth key it sends — at someone else's
// server.

// BeaconDoc is the published document. Keep it small and free of secrets:
// the topic is a capability, not a credential.
type BeaconDoc struct {
	Version     int    `json:"v"`
	IP          string `json:"ip"`
	ControlPort int    `json:"controlPort"`
	Hostname    string `json:"hostname,omitempty"`
	UpdatedAt   int64  `json:"updatedAt"`
	Changes     int    `json:"changes"`
	Instance    string `json:"instance"`
	Signature   string `json:"sig,omitempty"`
}

// BeaconIdentity is what makes a beacon findable and trustworthy. Written
// once to data/beacon.json (0600) and reused across restarts.
type BeaconIdentity struct {
	Topic     string `json:"topic"`
	VerifyKey string `json:"verifyKey"`
	Instance  string `json:"instance"`
}

// BeaconStatus is reported over the API and rendered by the dashboard.
type BeaconStatus struct {
	Enabled     bool   `json:"enabled"`
	Provider    string `json:"provider,omitempty"`
	ReadURL     string `json:"readUrl,omitempty"`
	Locator     string `json:"locator,omitempty"` // read URL + #verifyKey
	VerifyKey   string `json:"verifyKey,omitempty"`
	LastPublish int64  `json:"lastPublish,omitempty"`
	Status      string `json:"status,omitempty"`
}

type beacon struct {
	cfg      config.Beacon
	identity BeaconIdentity
	client   *http.Client

	mu       sync.RWMutex
	lastPub  time.Time
	status   string
	lastBody string
}

func newBeacon(cfg config.Beacon, controlPort int) *beacon {
	b := &beacon{
		cfg:    cfg,
		client: &http.Client{Timeout: httpTimeout},
		status: "not published yet",
	}
	if !cfg.Enabled {
		b.status = "disabled"
		return b
	}
	b.identity = loadOrCreateIdentity(cfg)
	return b
}

func (b *beacon) enabled() bool { return b.cfg.Enabled && b.identity.Topic != "" }

func (b *beacon) server() string {
	if b.cfg.Server != "" {
		return strings.TrimSuffix(b.cfg.Server, "/")
	}
	return "https://ntfy.sh"
}

// publishURL is where the daemon writes; readURL is where the dashboard
// reads. For ntfy they differ only by the query.
func (b *beacon) publishURL() string {
	if b.cfg.URL != "" {
		return b.cfg.URL
	}
	return b.server() + "/" + b.identity.Topic
}

func (b *beacon) readURL() string {
	if b.cfg.ReadURL != "" {
		return b.cfg.ReadURL
	}
	if b.cfg.URL != "" {
		return b.cfg.URL
	}
	// poll=1 returns what is retained and closes instead of streaming.
	return b.server() + "/" + b.identity.Topic + "/json?poll=1"
}

// Locator is the one string an operator needs to find this host again: the
// read URL plus the verify key in the fragment, which browsers never send
// to the server.
func (b *beacon) locator() string {
	if !b.enabled() {
		return ""
	}
	if b.identity.VerifyKey == "" {
		return b.readURL()
	}
	return b.readURL() + "#" + b.identity.VerifyKey
}

func (b *beacon) status_() BeaconStatus {
	b.mu.RLock()
	defer b.mu.RUnlock()
	st := BeaconStatus{
		Enabled:  b.cfg.Enabled,
		Provider: b.providerName(),
		Status:   b.status,
	}
	if b.enabled() {
		st.ReadURL = b.readURL()
		st.Locator = b.locator()
		st.VerifyKey = b.identity.VerifyKey
	}
	if !b.lastPub.IsZero() {
		st.LastPublish = b.lastPub.UnixMilli()
	}
	return st
}

func (b *beacon) providerName() string {
	if b.cfg.Provider != "" {
		return b.cfg.Provider
	}
	if b.cfg.URL != "" {
		return "custom"
	}
	return "ntfy"
}

// publish writes the current address to the beacon.
func (b *beacon) publish(ctx context.Context, doc BeaconDoc) {
	if !b.enabled() {
		return
	}
	doc.Version = 1
	doc.Instance = b.identity.Instance
	doc.UpdatedAt = time.Now().UnixMilli()
	doc.Signature = signBeacon(b.identity.VerifyKey, doc)

	body, err := json.Marshal(doc)
	if err != nil {
		b.setStatus("error: " + err.Error())
		return
	}

	method := b.cfg.Method
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, b.publishURL(), bytes.NewReader(body))
	if err != nil {
		b.setStatus("error: " + err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "honeystack-beacon/1")
	// ntfy shows these in its UI; harmless elsewhere.
	req.Header.Set("Title", "honeystack")
	req.Header.Set("Tags", "satellite")
	for k, v := range b.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		b.setStatus("error: " + err.Error())
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b.setStatus(fmt.Sprintf("error: HTTP %d %s", resp.StatusCode, truncate(strings.TrimSpace(string(respBody)), 80)))
		return
	}

	b.mu.Lock()
	b.lastPub = time.Now()
	b.status = "ok"
	b.lastBody = string(body)
	b.mu.Unlock()
}

func (b *beacon) setStatus(s string) {
	b.mu.Lock()
	b.status = s
	b.mu.Unlock()
	log.Printf("[beacon] %s", s)
}

// signBeacon is HMAC-SHA256 over the address fields, so a third party who
// knows the topic cannot point a dashboard somewhere else.
func signBeacon(key string, doc BeaconDoc) string {
	if key == "" {
		return ""
	}
	payload := fmt.Sprintf("%d|%s|%d|%s|%d|%s",
		doc.Version, doc.IP, doc.ControlPort, doc.Hostname, doc.UpdatedAt, doc.Instance)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// ---- identity persistence ----

func beaconIdentityPath(cfg config.Beacon) string {
	if cfg.CredentialsFile != "" {
		return cfg.CredentialsFile
	}
	return "data/beacon.json"
}

func loadOrCreateIdentity(cfg config.Beacon) BeaconIdentity {
	path := beaconIdentityPath(cfg)
	if data, err := os.ReadFile(path); err == nil {
		var id BeaconIdentity
		if err := json.Unmarshal(data, &id); err == nil && id.Topic != "" {
			return id
		}
		log.Printf("[beacon] %s unreadable; generating a new identity", path)
	}
	id := BeaconIdentity{
		Topic:     "honeystack-" + randomHex(16),
		VerifyKey: randomHex(32),
		Instance:  randomHex(4),
	}
	if cfg.Topic != "" {
		id.Topic = cfg.Topic
	}
	if err := saveIdentity(path, id); err != nil {
		log.Printf("[beacon] could not save %s: %v", path, err)
	}
	return id
}

func saveIdentity(path string, id BeaconIdentity) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(id, "", "  ")
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

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}
