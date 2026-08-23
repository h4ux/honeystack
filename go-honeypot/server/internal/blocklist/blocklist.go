// Package blocklist drops traffic from sources you do not want to record.
//
// A honeypot wants attackers, so blocking is not about defence — it is about
// signal. One scanner hammering a UDP port can push thousands of events a
// minute through the ring, evicting everything interesting; your own
// monitoring probes are noise; a broken client can loop forever. Blocking
// those keeps the record readable.
//
// Enforcement is in-process: connections from a blocked source are accepted
// and closed immediately, and datagrams are ignored. That works without
// root, without NET_ADMIN and without touching the host firewall, which is
// deliberate — the daemon runs unprivileged. For kernel-level dropping, the
// dashboard shows the equivalent nftables/iptables command to run yourself.
package blocklist

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Entry is one blocked address or range.
type Entry struct {
	Value   string `json:"value"` // "1.2.3.4" or "1.2.3.0/24"
	Reason  string `json:"reason,omitempty"`
	AddedAt int64  `json:"addedAt"`
	AddedBy string `json:"addedBy,omitempty"`
	Hits    int64  `json:"hits"`
	LastHit int64  `json:"lastHit,omitempty"`

	ip  net.IP     // parsed form, not serialised
	net *net.IPNet // set when Value is a CIDR
}

func (e *Entry) matches(ip net.IP) bool {
	if e.net != nil {
		return e.net.Contains(ip)
	}
	return e.ip != nil && e.ip.Equal(ip)
}

// List is a set of blocked addresses, persisted as JSON.
type List struct {
	mu      sync.RWMutex
	entries map[string]*Entry
	// cidrs mirrors the subset of entries that are ranges, so the common
	// case (exact addresses) stays a single map lookup per connection.
	cidrs []*Entry
	path  string

	dirty    atomic.Bool
	closeCh  chan struct{}
	closeOne sync.Once
	wg       sync.WaitGroup
}

// New loads the list from disk (an absent file is an empty list) and starts
// a writer that persists hit counters periodically.
func New(path string) *List {
	if path == "" {
		path = "data/blocklist.json"
	}
	l := &List{entries: map[string]*Entry{}, path: path, closeCh: make(chan struct{})}
	l.load()
	l.wg.Add(1)
	go l.flusher()
	return l
}

// Normalise turns user input into a canonical key, and rejects anything that
// is not an address or range.
func Normalise(value string) (string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", fmt.Errorf("empty value")
	}
	// Accept "1.2.3.4:5678" by dropping the port, since that is what the
	// dashboard shows next to an event.
	if host, _, err := net.SplitHostPort(v); err == nil && host != "" {
		v = host
	}
	v = strings.TrimPrefix(v, "::ffff:")
	if strings.Contains(v, "/") {
		_, network, err := net.ParseCIDR(v)
		if err != nil {
			return "", fmt.Errorf("not a valid CIDR: %s", value)
		}
		return network.String(), nil
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return "", fmt.Errorf("not a valid IP address: %s", value)
	}
	return ip.String(), nil
}

// Add blocks an address or range. Adding an existing entry refreshes its
// reason rather than duplicating it.
func (l *List) Add(value, reason, by string) (Entry, error) {
	key, err := Normalise(value)
	if err != nil {
		return Entry{}, err
	}
	entry := &Entry{
		Value: key, Reason: strings.TrimSpace(reason),
		AddedAt: time.Now().UnixMilli(), AddedBy: by,
	}
	if strings.Contains(key, "/") {
		if _, network, err := net.ParseCIDR(key); err == nil {
			entry.net = network
		}
	} else {
		entry.ip = net.ParseIP(key)
	}

	l.mu.Lock()
	if existing, ok := l.entries[key]; ok {
		existing.Reason = entry.Reason
		existing.AddedBy = by
		out := *existing
		l.mu.Unlock()
		l.dirty.Store(true)
		l.save()
		return out, nil
	}
	l.entries[key] = entry
	l.rebuildCIDRsLocked()
	out := *entry
	l.mu.Unlock()
	l.dirty.Store(true)
	l.save()
	return out, nil
}

// Remove unblocks an address. It reports whether anything was removed.
func (l *List) Remove(value string) bool {
	key, err := Normalise(value)
	if err != nil {
		key = strings.TrimSpace(value) // allow removing a malformed leftover
	}
	l.mu.Lock()
	_, ok := l.entries[key]
	if ok {
		delete(l.entries, key)
		l.rebuildCIDRsLocked()
	}
	l.mu.Unlock()
	if ok {
		l.dirty.Store(true)
		l.save()
	}
	return ok
}

// Blocked reports whether an address is blocked, counting the hit. It is on
// the accept path of every listener, so the common case is one map lookup.
func (l *List) Blocked(addr string) bool {
	if l == nil {
		return false
	}
	l.mu.RLock()
	if len(l.entries) == 0 {
		l.mu.RUnlock()
		return false
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil && h != "" {
		host = h
	}
	host = strings.TrimPrefix(host, "::ffff:")

	entry := l.entries[host]
	if entry == nil && len(l.cidrs) > 0 {
		if ip := net.ParseIP(host); ip != nil {
			for _, c := range l.cidrs {
				if c.matches(ip) {
					entry = c
					break
				}
			}
		}
	}
	l.mu.RUnlock()
	if entry == nil {
		return false
	}
	atomic.AddInt64(&entry.Hits, 1)
	atomic.StoreInt64(&entry.LastHit, time.Now().UnixMilli())
	l.dirty.Store(true)
	return true
}

// Entries returns a snapshot, most recently added first.
func (l *List) Entries() []Entry {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	out := make([]Entry, 0, len(l.entries))
	for _, e := range l.entries {
		out = append(out, Entry{
			Value: e.Value, Reason: e.Reason, AddedAt: e.AddedAt, AddedBy: e.AddedBy,
			Hits: atomic.LoadInt64(&e.Hits), LastHit: atomic.LoadInt64(&e.LastHit),
		})
	}
	l.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].AddedAt > out[j].AddedAt })
	return out
}

// Len is the number of entries.
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

func (l *List) rebuildCIDRsLocked() {
	l.cidrs = l.cidrs[:0]
	for _, e := range l.entries {
		if e.net != nil {
			l.cidrs = append(l.cidrs, e)
		}
	}
}

// Guard wraps a listener so blocked sources never reach the handler: the
// connection is accepted (there is no way to refuse one from user space) and
// closed immediately, without a session, an event or a reply.
func (l *List) Guard(inner net.Listener) net.Listener {
	if l == nil {
		return inner
	}
	return &guardedListener{Listener: inner, list: l}
}

type guardedListener struct {
	net.Listener
	list *List
}

func (g *guardedListener) Accept() (net.Conn, error) {
	for {
		conn, err := g.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if g.list.Blocked(conn.RemoteAddr().String()) {
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}

// ---- persistence ----

func (l *List) load() {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return
	}
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range entries {
		e := entries[i]
		key, err := Normalise(e.Value)
		if err != nil {
			continue
		}
		e.Value = key
		if strings.Contains(key, "/") {
			if _, network, err := net.ParseCIDR(key); err == nil {
				e.net = network
			}
		} else {
			e.ip = net.ParseIP(key)
		}
		copied := e
		l.entries[key] = &copied
	}
	l.rebuildCIDRsLocked()
}

func (l *List) save() {
	entries := l.Entries()
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	if err := os.Rename(tmp, l.path); err != nil {
		_ = os.Remove(tmp)
		return
	}
	l.dirty.Store(false)
}

// flusher persists hit counters without writing on every dropped packet.
func (l *List) flusher() {
	defer l.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-l.closeCh:
			return
		case <-ticker.C:
			if l.dirty.Load() && l.Len() > 0 {
				l.save()
			}
		}
	}
}

func (l *List) Close() {
	if l == nil {
		return
	}
	l.closeOne.Do(func() {
		close(l.closeCh)
		l.wg.Wait()
		if l.dirty.Load() {
			l.save()
		}
	})
}
