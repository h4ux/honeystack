// Package geoip turns attacker IPs into countries.
//
// There is no bundled database: country data comes from a public HTTP
// lookup service, cached on disk so a given IP is only ever asked about
// once. Lookups happen on a background worker, so a honeypot handler never
// waits on the network, and the cache is what every read path consults.
//
// Privacy note: enabling this sends attacker IPs (not your own traffic) to
// the configured provider. Set geoip.enabled to false to keep everything
// local.
package geoip

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
)

// Location is what we keep about one IP.
type Location struct {
	IP          string `json:"ip"`
	CountryCode string `json:"countryCode,omitempty"`
	Country     string `json:"country,omitempty"`
	City        string `json:"city,omitempty"`
	Region      string `json:"region,omitempty"`
	Org         string `json:"org,omitempty"`
	ASN         string `json:"asn,omitempty"`
	Private     bool   `json:"private,omitempty"`
	Failed      bool   `json:"failed,omitempty"`
	TS          int64  `json:"ts"`
}

// Resolved reports whether this entry carries a usable country.
func (l Location) Resolved() bool { return l.CountryCode != "" || l.Private }

type Resolver struct {
	cfg    config.GeoIP
	client *http.Client

	mu    sync.RWMutex
	cache map[string]Location
	dirty bool

	queue   chan string
	pending map[string]struct{}
	pendMu  sync.Mutex

	closeOnce sync.Once
	closeCh   chan struct{}
	wg        sync.WaitGroup

	lookups  atomic.Int64
	failures atomic.Int64
}

const (
	defaultProviderURL = "https://ipwho.is/{ip}"
	defaultTTLHours    = 720 // 30 days: country data barely moves
	defaultTimeoutMs   = 4000
	defaultRatePerMin  = 40
	maxCacheEntries    = 200000
)

// New builds a resolver. It is safe to use even when disabled — every
// lookup simply misses.
func New(cfg config.GeoIP) *Resolver {
	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultTimeoutMs * time.Millisecond
	}
	r := &Resolver{
		cfg:     cfg,
		client:  &http.Client{Timeout: timeout},
		cache:   map[string]Location{},
		queue:   make(chan string, 4096),
		pending: map[string]struct{}{},
		closeCh: make(chan struct{}),
	}
	r.loadCache()
	if cfg.Enabled {
		r.wg.Add(1)
		go r.worker()
	}
	r.wg.Add(1)
	go r.flusher()
	return r
}

func (r *Resolver) Enabled() bool { return r.cfg.Enabled }

// Lookup returns what we know right now. A miss queues a background lookup
// and returns false — callers never block.
func (r *Resolver) Lookup(ip string) (Location, bool) {
	if ip == "" {
		return Location{}, false
	}
	if loc, ok := privateLocation(ip); ok {
		return loc, true
	}
	r.mu.RLock()
	loc, ok := r.cache[ip]
	r.mu.RUnlock()
	if ok && !r.expired(loc) {
		return loc, loc.Resolved()
	}
	r.Queue(ip)
	return Location{}, false
}

// Annotate is the shape the event log wants: country name, ISO code and the
// network operator, or ok=false when the IP is not known yet.
func (r *Resolver) Annotate(ip string) (country, code, org string, ok bool) {
	loc, found := r.Lookup(ip)
	if !found {
		return "", "", "", false
	}
	return loc.Country, loc.CountryCode, loc.Org, true
}

// Queue schedules a lookup if the IP is worth asking about.
func (r *Resolver) Queue(ip string) {
	if !r.cfg.Enabled || ip == "" {
		return
	}
	if _, isPrivate := privateLocation(ip); isPrivate {
		return
	}
	r.mu.RLock()
	loc, cached := r.cache[ip]
	r.mu.RUnlock()
	if cached && !r.expired(loc) {
		return
	}
	r.pendMu.Lock()
	if _, dup := r.pending[ip]; dup {
		r.pendMu.Unlock()
		return
	}
	r.pending[ip] = struct{}{}
	r.pendMu.Unlock()

	select {
	case r.queue <- ip:
	default:
		// Queue full: drop it, the next event from this IP will retry.
		r.pendMu.Lock()
		delete(r.pending, ip)
		r.pendMu.Unlock()
	}
}

// Batch returns everything known for these IPs and queues the rest.
func (r *Resolver) Batch(ips []string) map[string]Location {
	out := make(map[string]Location, len(ips))
	for _, ip := range ips {
		if loc, ok := r.Lookup(ip); ok {
			out[ip] = loc
		}
	}
	return out
}

// Stats describes the cache for the dashboard.
type Stats struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
	Cached   int    `json:"cached"`
	Lookups  int64  `json:"lookups"`
	Failures int64  `json:"failures"`
	Queued   int    `json:"queued"`
}

func (r *Resolver) Stats() Stats {
	r.mu.RLock()
	cached := len(r.cache)
	r.mu.RUnlock()
	r.pendMu.Lock()
	queued := len(r.pending)
	r.pendMu.Unlock()
	return Stats{
		Enabled:  r.cfg.Enabled,
		Provider: r.providerURL(),
		Cached:   cached,
		Lookups:  r.lookups.Load(),
		Failures: r.failures.Load(),
		Queued:   queued,
	}
}

func (r *Resolver) Close() {
	r.closeOnce.Do(func() {
		close(r.closeCh)
		r.wg.Wait()
		r.saveCache()
	})
}

func (r *Resolver) expired(loc Location) bool {
	ttl := time.Duration(r.cfg.TTLHours) * time.Hour
	if ttl <= 0 {
		ttl = defaultTTLHours * time.Hour
	}
	// Failed lookups are retried much sooner than successful ones.
	if loc.Failed {
		ttl = time.Hour
	}
	return time.Since(time.UnixMilli(loc.TS)) > ttl
}

func (r *Resolver) providerURL() string {
	if r.cfg.URL != "" {
		return r.cfg.URL
	}
	switch strings.ToLower(r.cfg.Provider) {
	case "", "ipwho.is", "ipwhois":
		return defaultProviderURL
	case "ip-api", "ip-api.com":
		return "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,regionName,as,org,isp"
	case "ipinfo", "ipinfo.io":
		return "https://ipinfo.io/{ip}/json"
	default:
		// Unknown name: treat it as a host and hope it takes /{ip}.
		return "https://" + strings.TrimSuffix(r.cfg.Provider, "/") + "/{ip}"
	}
}

// worker drains the queue at the configured rate.
func (r *Resolver) worker() {
	defer r.wg.Done()
	perMin := r.cfg.RateLimitPerMin
	if perMin <= 0 {
		perMin = defaultRatePerMin
	}
	interval := time.Minute / time.Duration(perMin)
	if interval < 50*time.Millisecond {
		interval = 50 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.closeCh:
			return
		case ip := <-r.queue:
			select {
			case <-r.closeCh:
				return
			case <-ticker.C:
			}
			loc := r.fetch(ip)
			r.mu.Lock()
			if len(r.cache) < maxCacheEntries {
				r.cache[ip] = loc
				r.dirty = true
			}
			r.mu.Unlock()
			r.pendMu.Lock()
			delete(r.pending, ip)
			r.pendMu.Unlock()
		}
	}
}

func (r *Resolver) fetch(ip string) Location {
	url := strings.ReplaceAll(r.providerURL(), "{ip}", ip)
	now := time.Now().UnixMilli()
	r.lookups.Add(1)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		r.failures.Add(1)
		return Location{IP: ip, Failed: true, TS: now}
	}
	req.Header.Set("User-Agent", "honeystack-geoip/1")
	resp, err := r.client.Do(req)
	if err != nil {
		r.failures.Add(1)
		return Location{IP: ip, Failed: true, TS: now}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		r.failures.Add(1)
		return Location{IP: ip, Failed: true, TS: now}
	}
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		r.failures.Add(1)
		return Location{IP: ip, Failed: true, TS: now}
	}
	loc := parseProviderResponse(ip, raw)
	loc.TS = now
	if loc.CountryCode == "" {
		loc.Failed = true
		r.failures.Add(1)
	}
	return loc
}

// parseProviderResponse reads the field names used by the common free
// providers (ipwho.is, ip-api.com, ipinfo.io) out of one JSON object.
func parseProviderResponse(ip string, raw map[string]any) Location {
	loc := Location{IP: ip}
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := raw[k]; ok {
				if s, ok := v.(string); ok && s != "" {
					return s
				}
			}
		}
		return ""
	}
	loc.Country = str("country", "country_name")
	loc.CountryCode = strings.ToUpper(str("countryCode", "country_code", "country"))
	if len(loc.CountryCode) > 2 {
		// ipinfo returns only "country" as a 2-letter code; anything longer
		// here means we picked up a full name by mistake.
		loc.CountryCode = ""
	}
	loc.City = str("city")
	loc.Region = str("region", "regionName", "region_name")
	loc.Org = str("org", "isp", "as")
	loc.ASN = str("asn")

	// ipwho.is nests the network operator under "connection".
	if conn, ok := raw["connection"].(map[string]any); ok {
		if loc.Org == "" {
			if s, ok := conn["org"].(string); ok {
				loc.Org = s
			} else if s, ok := conn["isp"].(string); ok {
				loc.Org = s
			}
		}
		if loc.ASN == "" {
			switch v := conn["asn"].(type) {
			case float64:
				loc.ASN = fmt.Sprintf("AS%d", int(v))
			case string:
				loc.ASN = v
			}
		}
	}
	// ip-api.com puts "AS15169 Google LLC" in "as".
	if loc.ASN == "" && strings.HasPrefix(loc.Org, "AS") {
		if i := strings.Index(loc.Org, " "); i > 0 {
			loc.ASN = loc.Org[:i]
			loc.Org = strings.TrimSpace(loc.Org[i+1:])
		}
	}
	if loc.Country == "" && loc.CountryCode != "" {
		loc.Country = loc.CountryCode
	}
	return loc
}

// privateLocation labels addresses that no lookup service can resolve.
func privateLocation(ipStr string) (Location, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return Location{}, false
	}
	switch {
	case ip.IsLoopback():
		return Location{IP: ipStr, Country: "Loopback", CountryCode: "", Private: true}, true
	case ip.IsPrivate():
		return Location{IP: ipStr, Country: "Private network", CountryCode: "", Private: true}, true
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return Location{IP: ipStr, Country: "Link-local", CountryCode: "", Private: true}, true
	case ip.IsUnspecified():
		return Location{IP: ipStr, Country: "Unspecified", CountryCode: "", Private: true}, true
	}
	return Location{}, false
}

// ---- disk cache ----

func (r *Resolver) cachePath() string {
	if r.cfg.CacheFile != "" {
		return r.cfg.CacheFile
	}
	return "data/geoip-cache.json"
}

func (r *Resolver) loadCache() {
	path := r.cachePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var entries map[string]Location
	if err := json.Unmarshal(data, &entries); err != nil {
		return
	}
	r.mu.Lock()
	for ip, loc := range entries {
		if loc.IP == "" {
			loc.IP = ip
		}
		r.cache[ip] = loc
	}
	r.mu.Unlock()
}

func (r *Resolver) saveCache() {
	r.mu.RLock()
	if !r.dirty {
		r.mu.RUnlock()
		return
	}
	snapshot := make(map[string]Location, len(r.cache))
	for ip, loc := range r.cache {
		snapshot[ip] = loc
	}
	r.mu.RUnlock()

	path := r.cachePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		return
	}
	r.mu.Lock()
	r.dirty = false
	r.mu.Unlock()
}

// flusher persists the cache periodically so a crash does not throw away
// everything we learned.
func (r *Resolver) flusher() {
	defer r.wg.Done()
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-r.closeCh:
			return
		case <-ticker.C:
			r.saveCache()
		}
	}
}
