// Package eventlog stores honeypot events in memory (ring buffer) and
// appends every event to a newline-delimited JSON file for persistence.
package eventlog

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Event struct {
	ID         uint64         `json:"id"`
	TS         int64          `json:"ts"`
	Service    string         `json:"service"`
	Type       string         `json:"type"`
	RemoteIP   string         `json:"remoteIp,omitempty"`
	RemotePort int            `json:"remotePort,omitempty"`
	LocalPort  int            `json:"localPort,omitempty"`
	Username   string         `json:"username,omitempty"`
	Password   string         `json:"password,omitempty"`
	Command    string         `json:"command,omitempty"`
	SessionID  string         `json:"sessionId,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
	// Geo fields are filled from the geoip cache — at log time when the IP
	// is already known, otherwise on the way out to a client.
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	Org         string `json:"org,omitempty"`
}

type Session struct {
	ID           string  `json:"id"`
	Service      string  `json:"service"`
	RemoteIP     string  `json:"remoteIp,omitempty"`
	RemotePort   int     `json:"remotePort,omitempty"`
	Username     string  `json:"username,omitempty"`
	OpenedAt     int64   `json:"openedAt"`
	ClosedAt     int64   `json:"closedAt,omitempty"`
	CommandCount int     `json:"commandCount"`
	Country      string  `json:"country,omitempty"`
	CountryCode  string  `json:"countryCode,omitempty"`
	Org          string  `json:"org,omitempty"`
	Events       []Event `json:"events,omitempty"`
}

// Stats is the aggregate view the dashboard renders. Counters are over
// everything still retained (memory ring + whatever was replayed from
// events.ndjson), so they grow until the ring wraps.
type Stats struct {
	Total          int   `json:"total"`
	Last24h        int   `json:"last24h"`
	LastHour       int   `json:"lastHour"`
	UniqueIPs      int   `json:"uniqueIps"`
	UniqueIPs24h   int   `json:"uniqueIps24h"`
	ActiveSessions int   `json:"activeSessions"`
	TotalSessions  int   `json:"totalSessions"`
	ShellSessions  int   `json:"shellSessions"`
	Commands       int   `json:"commands"`
	Attempts       int   `json:"attempts"`
	Accepted       int   `json:"accepted"`
	Rejected       int   `json:"rejected"`
	FirstEventTS   int64 `json:"firstEventTs"`
	LastEventTS    int64 `json:"lastEventTs"`

	// This run, as opposed to everything retained: the ring is rehydrated
	// from events.ndjson on boot, so most counters above can describe
	// traffic from previous runs.
	StartedAt            int64 `json:"startedAt"`
	UptimeMs             int64 `json:"uptimeMs"`
	EventsSinceStart     int   `json:"eventsSinceStart"`
	TrafficSinceStart    int   `json:"trafficSinceStart"`
	FirstEventSinceStart int64 `json:"firstEventSinceStart,omitempty"`
	// Milliseconds from daemon start to the first *inbound* event of this
	// run; -1 while nothing has arrived yet. The daemon's own startup
	// bookkeeping does not count as traffic.
	TimeToFirstEventMs int64   `json:"timeToFirstEventMs"`
	FirstEventService  string  `json:"firstEventService,omitempty"`
	EventsPerMin       float64 `json:"eventsPerMin"`
	PeakHour           string  `json:"peakHour"`
	PeakHourCount      int     `json:"peakHourCount"`

	ByService []KV `json:"byService"`
	ByType    []KV `json:"byType"`
	// Hourly is the last 24 hours in chronological order (one bucket per
	// hour, UTC) — not a top-N list, so it can be plotted as a series.
	Hourly   []KV     `json:"hourly"`
	Timeline []Bucket `json:"timeline"`
	Daily    []Bucket `json:"daily"`
	Heatmap  Heatmap  `json:"heatmap"`

	TopIPs       []KV           `json:"topIps"`
	TopCountries []CountryCount `json:"topCountries"`
	TopCreds     []CredCount    `json:"topCreds"`
	TopCommands  []KV           `json:"topCommands"`
	TopUsernames []KV           `json:"topUsernames"`
	TopPasswords []KV           `json:"topPasswords"`
	TopPorts     []KV           `json:"topPorts"`
	TopPaths     []KV           `json:"topPaths"`
	TopClients   []KV           `json:"topClients"`
	Services     []ServiceStat  `json:"serviceStats"`
}

// Bucket is one slot of a time series.
type Bucket struct {
	Label     string `json:"label"`
	TS        int64  `json:"ts"`
	Count     int    `json:"count"`
	Attempts  int    `json:"attempts"`
	Accepted  int    `json:"accepted"`
	UniqueIPs int    `json:"uniqueIps"`
}

// Heatmap is a weekday x hour grid (UTC). Grid is 7*24 entries indexed
// as weekday*24+hour with Monday as weekday 0.
type Heatmap struct {
	Max  int   `json:"max"`
	Grid []int `json:"grid"`
}

// CountryCount is one row of the geo breakdown.
type CountryCount struct {
	Code      string `json:"code"`
	Name      string `json:"name"`
	Count     int    `json:"count"`
	UniqueIPs int    `json:"uniqueIps"`
}

// ServiceStat is the per-listener breakdown behind the service table.
type ServiceStat struct {
	Service   string `json:"service"`
	Port      int    `json:"port"`
	Events    int    `json:"events"`
	UniqueIPs int    `json:"uniqueIps"`
	Attempts  int    `json:"attempts"`
	Accepted  int    `json:"accepted"`
	Commands  int    `json:"commands"`
	FirstSeen int64  `json:"firstSeen,omitempty"`
	LastSeen  int64  `json:"lastSeen"`

	// Per-listener view of this run only.
	EventsSinceStart int   `json:"eventsSinceStart"`
	FirstSinceStart  int64 `json:"firstSinceStart,omitempty"`
	// Milliseconds from daemon start until this listener's first hit of
	// the run; -1 while it has not been touched yet.
	TimeToFirstMs int64 `json:"timeToFirstMs"`
}

type KV struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type CredCount struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Count    int    `json:"count"`
}

type Subscriber func(Event)

// Geo resolves an IP to a country. It is satisfied by internal/geoip and
// kept as an interface so the event log has no opinion about where country
// data comes from (or whether it exists at all).
type Geo interface {
	Annotate(ip string) (country, code, org string, ok bool)
	Queue(ip string)
}

type Store struct {
	mu       sync.RWMutex
	events   []Event
	max      int
	nextID   uint64
	sessions map[string]*Session

	file    *os.File
	writer  *bufio.Writer
	flushCh chan struct{}
	closeCh chan struct{}

	subs   map[uint64]Subscriber
	subSeq uint64
	subMu  sync.RWMutex

	geoMu sync.RWMutex
	geo   Geo

	// "Since start" bookkeeping. Replayed events never pass through Log,
	// so counting there is what separates this run from history.
	startedAt         int64
	firstSinceStart   int64
	firstSinceService string
	eventsSinceStart  int
	trafficSinceStart int
	svcFirstSince     map[string]int64
	svcEventsSince    map[string]int

	opts      Options
	logPath   string
	fileBytes int64
	closeOnce sync.Once

	statsMu    sync.Mutex
	statsCache Stats
	statsAt    time.Time
}

// SetGeo attaches (or clears) the country resolver.
func (s *Store) SetGeo(g Geo) {
	s.geoMu.Lock()
	s.geo = g
	s.geoMu.Unlock()
}

func (s *Store) geoResolver() Geo {
	s.geoMu.RLock()
	defer s.geoMu.RUnlock()
	return s.geo
}

// annotate fills the geo fields of one event from the cache. Events are
// annotated on the way out as well as at log time, so an IP that was
// unknown when it first hit still shows a country once the lookup lands.
func (s *Store) annotate(e *Event) {
	if e.RemoteIP == "" || e.CountryCode != "" || e.Country != "" {
		return
	}
	g := s.geoResolver()
	if g == nil {
		return
	}
	if country, code, org, ok := g.Annotate(e.RemoteIP); ok {
		e.Country, e.CountryCode, e.Org = country, code, org
	}
}

func (s *Store) annotateSession(sess *Session) {
	if sess.RemoteIP == "" || sess.CountryCode != "" || sess.Country != "" {
		return
	}
	g := s.geoResolver()
	if g == nil {
		return
	}
	if country, code, org, ok := g.Annotate(sess.RemoteIP); ok {
		sess.Country, sess.CountryCode, sess.Org = country, code, org
	}
}

// Options bound what the store keeps. Every field has a sane default, so
// Options{} is valid.
type Options struct {
	MaxRows        int // events held in memory
	MaxSessions    int // rows in the session table
	MaxDetailBytes int // per detail value; the whole map gets 4x this
	MaxLogFileMB   int // rotate events.ndjson past this; -1 disables
	StatsCacheMs   int // serve the aggregate from cache for this long
}

const (
	defaultMaxRows        = 25000
	defaultMaxSessions    = 20000
	defaultMaxDetailBytes = 2048
	defaultMaxLogFileMB   = 128
	defaultStatsCacheMs   = 3000
)

func (o Options) withDefaults() Options {
	if o.MaxRows <= 0 {
		o.MaxRows = defaultMaxRows
	}
	if o.MaxSessions <= 0 {
		o.MaxSessions = defaultMaxSessions
	}
	if o.MaxDetailBytes <= 0 {
		o.MaxDetailBytes = defaultMaxDetailBytes
	}
	if o.MaxLogFileMB == 0 {
		o.MaxLogFileMB = defaultMaxLogFileMB
	}
	if o.StatsCacheMs <= 0 {
		o.StatsCacheMs = defaultStatsCacheMs
	}
	return o
}

// New opens the store with default limits. Use NewWithOptions to change them.
func New(logPath string, maxRows int) (*Store, error) {
	return NewWithOptions(logPath, Options{MaxRows: maxRows})
}

func NewWithOptions(logPath string, opts Options) (*Store, error) {
	opts = opts.withDefaults()
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	s := &Store{
		max:            opts.MaxRows,
		opts:           opts,
		logPath:        logPath,
		sessions:       map[string]*Session{},
		file:           f,
		writer:         bufio.NewWriter(f),
		flushCh:        make(chan struct{}, 1),
		closeCh:        make(chan struct{}),
		subs:           map[uint64]Subscriber{},
		startedAt:      time.Now().UnixMilli(),
		svcFirstSince:  map[string]int64{},
		svcEventsSince: map[string]int{},
	}
	if fi, err := f.Stat(); err == nil {
		s.fileBytes = fi.Size()
	}
	// Rehydrate from the NDJSON log so a dashboard that connects after a
	// restart still sees history, not just events since the daemon booted.
	if err := s.loadFromDisk(logPath, opts.MaxRows); err != nil {
		log.Printf("[eventlog] could not replay %s: %v", logPath, err)
	}
	go s.flusher()
	return s, nil
}

// loadFromDisk replays up to maxRows trailing records from the NDJSON log.
func (s *Store) loadFromDisk(logPath string, maxRows int) error {
	f, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	// Only the tail can survive the ring anyway, so seek instead of reading
	// (and allocating) a log that may be gigabytes after weeks of scanning.
	// 4 KB per event is a generous ceiling for the rows we keep.
	if fi, err := f.Stat(); err == nil {
		budget := int64(maxRows) * 4096
		if cap := int64(s.opts.MaxLogFileMB) * 1024 * 1024; cap > 0 && cap < budget {
			budget = cap
		}
		if budget > 0 && fi.Size() > budget {
			if _, err := f.Seek(fi.Size()-budget, io.SeekStart); err == nil {
				// The first line after an arbitrary offset is a fragment.
				br := bufio.NewReader(f)
				if _, err := br.ReadString('\n'); err == nil {
					log.Printf("[eventlog] replaying the last %d MB of %s (file is %d MB)",
						budget/1024/1024, logPath, fi.Size()/1024/1024)
					return s.replay(br, maxRows)
				}
			}
		}
	}

	return s.replay(f, maxRows)
}

func (s *Store) replay(r io.Reader, maxRows int) error {
	ring := make([]Event, 0, 4096)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		ring = append(ring, e)
		if len(ring) > maxRows {
			ring = ring[len(ring)-maxRows:]
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = ring
	for _, e := range ring {
		if e.ID > s.nextID {
			s.nextID = e.ID
		}
		if e.SessionID == "" {
			continue
		}
		sess, ok := s.sessions[e.SessionID]
		if !ok {
			sess = &Session{
				ID: e.SessionID, Service: e.Service,
				RemoteIP: e.RemoteIP, RemotePort: e.RemotePort,
				OpenedAt: e.TS,
			}
			s.sessions[e.SessionID] = sess
		}
		if sess.Username == "" && e.Username != "" {
			sess.Username = e.Username
		}
		if e.Type == "command" || e.Type == "exec" {
			sess.CommandCount++
		}
		if e.Type == "connection_closed" && e.TS > sess.ClosedAt {
			sess.ClosedAt = e.TS
		}
	}
	// Anything still open from a previous process is not really live.
	for _, sess := range s.sessions {
		if sess.ClosedAt == 0 {
			sess.ClosedAt = sess.OpenedAt
		}
	}
	if n := len(ring); n > 0 {
		log.Printf("[eventlog] replayed %d events from %s", n, s.logPath)
	}
	return nil
}

func (s *Store) flusher() {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-s.closeCh:
			s.mu.Lock()
			_ = s.writer.Flush()
			_ = s.file.Sync()
			_ = s.file.Close()
			s.mu.Unlock()
			return
		case <-tick.C:
			s.mu.Lock()
			_ = s.writer.Flush()
			s.mu.Unlock()
		case <-s.flushCh:
			s.mu.Lock()
			_ = s.writer.Flush()
			s.mu.Unlock()
		}
	}
}

// Close stops the flusher and drains the write buffer. Safe to call more
// than once: a second call used to panic on the closed channel.
func (s *Store) Close() {
	s.closeOnce.Do(func() { close(s.closeCh) })
}

// Log appends an event, notifies subscribers, and returns the stored copy.
// capDetails keeps one captured request from pinning kilobytes in the ring
// for the rest of the process's life. Values are truncated, not dropped:
// the marker makes it obvious in the dashboard that there was more.
func capDetails(details map[string]any, maxValue int) map[string]any {
	if len(details) == 0 || maxValue <= 0 {
		return details
	}
	// maxDetailBytes is the ceiling for the whole map, not per value: under
	// an all-HTTP flood every event carries headers *and* a body, and a
	// per-value cap alone still let 25k events hold ~200 MB.
	budget := maxValue
	if maxValue > 256 {
		maxValue /= 2
	}
	out := make(map[string]any, len(details))
	spent := 0
	for k, v := range details {
		switch val := v.(type) {
		case string:
			if len(val) > maxValue {
				val = val[:maxValue] + "…[truncated]"
			}
			if spent+len(val) > budget {
				out[k] = "…[dropped: details budget]"
				continue
			}
			spent += len(val)
			out[k] = val
		case map[string]string:
			trimmed := make(map[string]string, len(val))
			for hk, hv := range val {
				if len(hv) > maxValue {
					hv = hv[:maxValue] + "…"
				}
				if spent+len(hv) > budget {
					continue
				}
				spent += len(hv)
				trimmed[hk] = hv
			}
			out[k] = trimmed
		default:
			out[k] = v
		}
	}
	return out
}

func (s *Store) Log(e Event) Event {
	if e.TS == 0 {
		e.TS = time.Now().UnixMilli()
	}
	e.Details = capDetails(e.Details, s.opts.MaxDetailBytes)
	if max := s.opts.MaxDetailBytes * 8; max > 0 && len(e.Command) > max {
		e.Command = e.Command[:max] + "…[truncated]"
	}
	if e.RemoteIP != "" {
		if g := s.geoResolver(); g != nil {
			s.annotate(&e)
			if e.CountryCode == "" {
				// Not cached yet: ask in the background so the next event
				// (and every read path) has it.
				g.Queue(e.RemoteIP)
			}
		}
	}
	s.mu.Lock()
	s.nextID++
	e.ID = s.nextID
	s.eventsSinceStart++
	if !isOwnBookkeeping(e) {
		s.trafficSinceStart++
		if s.firstSinceStart == 0 {
			s.firstSinceStart = e.TS
			s.firstSinceService = e.Service
		}
	}
	if e.Service != "" {
		if _, seen := s.svcFirstSince[e.Service]; !seen {
			s.svcFirstSince[e.Service] = e.TS
		}
		s.svcEventsSince[e.Service]++
	}
	s.events = append(s.events, e)
	if len(s.events) > s.max {
		s.events = s.events[len(s.events)-s.max:]
	}
	if e.SessionID != "" {
		if sess, ok := s.sessions[e.SessionID]; ok && e.Type == "command" {
			sess.CommandCount++
		}
	}
	b, _ := json.Marshal(e)
	n, _ := s.writer.Write(b)
	n2, _ := s.writer.Write([]byte("\n"))
	s.fileBytes += int64(n + n2)
	if s.opts.MaxLogFileMB > 0 && s.fileBytes > int64(s.opts.MaxLogFileMB)*1024*1024 {
		s.rotateLocked()
	}
	s.mu.Unlock()
	s.fanout(e)
	return e
}

func (s *Store) OpenSession(sess Session) {
	if sess.OpenedAt == 0 {
		sess.OpenedAt = time.Now().UnixMilli()
	}
	s.mu.Lock()
	s.sessions[sess.ID] = &sess
	if len(s.sessions) > s.opts.MaxSessions {
		s.pruneSessionsLocked()
	}
	s.mu.Unlock()
}

// pruneSessionsLocked drops the oldest closed sessions until the table is
// back under 80% of the cap. Nothing used to remove sessions at all, so a
// scanned host grew this map until the process was killed.
func (s *Store) pruneSessionsLocked() {
	target := s.opts.MaxSessions * 8 / 10
	if target < 1 {
		target = 1
	}
	type ref struct {
		id string
		ts int64
	}
	closed := make([]ref, 0, len(s.sessions))
	for id, sess := range s.sessions {
		if sess.ClosedAt != 0 {
			closed = append(closed, ref{id: id, ts: sess.OpenedAt})
		}
	}
	sort.Slice(closed, func(i, j int) bool { return closed[i].ts < closed[j].ts })
	for _, c := range closed {
		if len(s.sessions) <= target {
			break
		}
		delete(s.sessions, c.id)
	}
	// Still over the cap? Every session claims to be open — drop the oldest
	// of those too rather than grow without bound.
	if len(s.sessions) > s.opts.MaxSessions {
		open := make([]ref, 0, len(s.sessions))
		for id, sess := range s.sessions {
			open = append(open, ref{id: id, ts: sess.OpenedAt})
		}
		sort.Slice(open, func(i, j int) bool { return open[i].ts < open[j].ts })
		for _, c := range open {
			if len(s.sessions) <= target {
				break
			}
			delete(s.sessions, c.id)
		}
	}
}

// rotateLocked moves the NDJSON log aside once it passes the size cap,
// keeping exactly one previous generation. Caller holds s.mu.
func (s *Store) rotateLocked() {
	_ = s.writer.Flush()
	_ = s.file.Close()
	prev := s.logPath + ".1"
	_ = os.Remove(prev)
	if err := os.Rename(s.logPath, prev); err != nil {
		log.Printf("[eventlog] rotate failed: %v", err)
	}
	f, err := os.OpenFile(s.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("[eventlog] reopen after rotate failed: %v", err)
		return
	}
	s.file = f
	s.writer = bufio.NewWriter(f)
	s.fileBytes = 0
	log.Printf("[eventlog] rotated %s (kept one generation as %s)", s.logPath, prev)
}

func (s *Store) CloseSession(id string) {
	s.mu.Lock()
	if sess, ok := s.sessions[id]; ok {
		sess.ClosedAt = time.Now().UnixMilli()
	}
	s.mu.Unlock()
}

func (s *Store) SetSessionUsername(id, username string) {
	s.mu.Lock()
	if sess, ok := s.sessions[id]; ok && sess.Username == "" {
		sess.Username = username
	}
	s.mu.Unlock()
}

// SessionFilter narrows the session list. Every field is optional.
type SessionFilter struct {
	Service     string
	IP          string
	Username    string
	CountryCode string
	Status      string // active | closed | "" (both)
	MinCommands int
	Since       int64
	Until       int64
	Search      string // matches id, ip, username, service, country, org
	Sort        string // recent | oldest | commands | duration
	Limit       int
}

func (s *Store) Sessions(filter SessionFilter) []Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	needle := strings.ToLower(filter.Search)
	out := make([]Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		item := *sess
		item.Events = nil
		s.annotateSession(&item)
		if !sessionMatches(item, filter, needle) {
			continue
		}
		out = append(out, item)
	}
	switch filter.Sort {
	case "oldest":
		sort.Slice(out, func(i, j int) bool { return out[i].OpenedAt < out[j].OpenedAt })
	case "commands":
		sort.Slice(out, func(i, j int) bool { return out[i].CommandCount > out[j].CommandCount })
	case "duration":
		sort.Slice(out, func(i, j int) bool { return sessionDuration(out[i]) > sessionDuration(out[j]) })
	default:
		sort.Slice(out, func(i, j int) bool { return out[i].OpenedAt > out[j].OpenedAt })
	}
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out
}

func sessionDuration(sess Session) int64 {
	end := sess.ClosedAt
	if end == 0 {
		end = time.Now().UnixMilli()
	}
	return end - sess.OpenedAt
}

func sessionMatches(sess Session, f SessionFilter, needle string) bool {
	if f.Service != "" && sess.Service != f.Service {
		return false
	}
	if f.IP != "" && sess.RemoteIP != f.IP {
		return false
	}
	if f.Username != "" && !strings.EqualFold(sess.Username, f.Username) {
		return false
	}
	if f.CountryCode != "" && !strings.EqualFold(sess.CountryCode, f.CountryCode) {
		return false
	}
	switch strings.ToLower(f.Status) {
	case "active":
		if sess.ClosedAt != 0 {
			return false
		}
	case "closed":
		if sess.ClosedAt == 0 {
			return false
		}
	}
	if f.MinCommands > 0 && sess.CommandCount < f.MinCommands {
		return false
	}
	if f.Since > 0 && sess.OpenedAt < f.Since {
		return false
	}
	if f.Until > 0 && sess.OpenedAt > f.Until {
		return false
	}
	if needle != "" {
		hay := strings.ToLower(strings.Join([]string{
			sess.ID, sess.Service, sess.RemoteIP, sess.Username,
			sess.Country, sess.CountryCode, sess.Org,
		}, " "))
		if !strings.Contains(hay, needle) {
			return false
		}
	}
	return true
}

func (s *Store) Session(id string) (Session, bool) {
	s.mu.RLock()
	sess, ok := s.sessions[id]
	if !ok {
		s.mu.RUnlock()
		return Session{}, false
	}
	copy := *sess
	s.mu.RUnlock()
	s.annotateSession(&copy)

	s.mu.RLock()
	evts := make([]Event, 0, 32)
	for _, e := range s.events {
		if e.SessionID == id {
			s.annotate(&e)
			evts = append(evts, e)
		}
	}
	s.mu.RUnlock()
	copy.Events = evts
	return copy, true
}

type EventFilter struct {
	Service   string
	Type      string
	IP        string
	SessionID string
	Since     int64
	Until     int64
	Search    string
	Limit     int
}

func (s *Store) Events(f EventFilter) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 20000 {
		limit = 20000
	}
	needle := strings.ToLower(f.Search)
	out := make([]Event, 0, limit)
	// walk newest-first, collect up to limit, then reverse to time-ascending.
	for i := len(s.events) - 1; i >= 0 && len(out) < limit; i-- {
		e := s.events[i]
		if f.Service != "" && e.Service != f.Service {
			continue
		}
		if f.Type != "" && e.Type != f.Type {
			continue
		}
		if f.IP != "" && e.RemoteIP != f.IP {
			continue
		}
		if f.SessionID != "" && e.SessionID != f.SessionID {
			continue
		}
		if f.Since > 0 && e.TS < f.Since {
			continue
		}
		if f.Until > 0 && e.TS > f.Until {
			continue
		}
		if needle != "" && !eventMatches(e, needle) {
			continue
		}
		s.annotate(&e)
		out = append(out, e)
	}
	// reverse
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func eventMatches(e Event, needle string) bool {
	if strings.Contains(strings.ToLower(e.Username), needle) ||
		strings.Contains(strings.ToLower(e.Password), needle) ||
		strings.Contains(strings.ToLower(e.Command), needle) ||
		strings.Contains(strings.ToLower(e.RemoteIP), needle) ||
		strings.Contains(strings.ToLower(e.Service), needle) ||
		strings.Contains(strings.ToLower(e.Type), needle) {
		return true
	}
	for k, v := range e.Details {
		if strings.Contains(strings.ToLower(k), needle) {
			return true
		}
		if sv, ok := v.(string); ok && strings.Contains(strings.ToLower(sv), needle) {
			return true
		}
	}
	return false
}

// Range reports the timestamp of the oldest and newest retained events.
func (s *Store) Range() (int64, int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.events) == 0 {
		return 0, 0
	}
	return s.events[0].TS, s.events[len(s.events)-1].TS
}

// serviceAgg accumulates the per-listener counters while walking the
// event ring exactly once.
type serviceAgg struct {
	events       int
	commands     int
	firstSeen    int64
	authAttempt  int
	loginAttempt int
	authSuccess  int
	lastSeen     int64
	port         int
	ips          map[string]struct{}
}

// attempts reports how many credential attempts this service saw.
// SSH logs an auth_attempt for *every* try plus an auth_success on top,
// while the other listeners log either login_attempt (failed) or
// auth_success (accepted). Counting naively would double the SSH
// successes, so the shape of the data decides the formula.
func (a *serviceAgg) attempts() int {
	n := a.authAttempt + a.loginAttempt
	if a.authAttempt == 0 {
		n += a.authSuccess
	}
	return n
}

// isOwnBookkeeping reports whether an event is the daemon talking about
// itself (startup, listeners coming up or failing) rather than something
// that arrived over the network. "Time to first hit" means first real
// traffic, so these do not count.
func isOwnBookkeeping(e Event) bool {
	if e.Service == "system" {
		return true
	}
	switch e.Type {
	case "startup", "shutdown", "service_started", "service_stopped", "service_error", "server_error":
		return true
	}
	return false
}

// StartedAt reports when this daemon run began (milliseconds).
func (s *Store) StartedAt() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.startedAt
}

// Stats serves the aggregate from a short-lived cache: computing it walks
// the whole ring, and every connected dashboard asks for it on a timer.
func (s *Store) Stats() Stats {
	ttl := time.Duration(s.opts.StatsCacheMs) * time.Millisecond
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	if !s.statsAt.IsZero() && time.Since(s.statsAt) < ttl {
		cached := s.statsCache
		// Uptime is the one field that must not look frozen.
		cached.UptimeMs = time.Now().UnixMilli() - cached.StartedAt
		return cached
	}
	st := s.computeStats()
	s.statsCache = st
	s.statsAt = time.Now()
	return st
}

func (s *Store) computeStats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	cutoff24 := now.Add(-24 * time.Hour).UnixMilli()
	cutoff1h := now.Add(-time.Hour).UnixMilli()

	stats := Stats{Total: len(s.events)}
	if len(s.events) > 0 {
		stats.FirstEventTS = s.events[0].TS
		stats.LastEventTS = s.events[len(s.events)-1].TS
	}

	typeCount := map[string]int{}
	ipCount := map[string]int{}
	credCount := map[string]int{}
	credInfo := map[string]CredCount{}
	cmdCount := map[string]int{}
	userCount := map[string]int{}
	passCount := map[string]int{}
	portCount := map[string]int{}
	pathCount := map[string]int{}
	clientCount := map[string]int{}
	seenIPs := map[string]struct{}{}
	seenIPs24 := map[string]struct{}{}
	svcAggs := map[string]*serviceAgg{}

	// Resolve each distinct IP once per call instead of per event.
	geo := s.geoResolver()
	type geoEntry struct{ code, name string }
	geoMemo := map[string]geoEntry{}
	countryCount := map[string]int{}
	countryName := map[string]string{}
	countryIPs := map[string]map[string]struct{}{}
	lookupGeo := func(ip string) geoEntry {
		if entry, ok := geoMemo[ip]; ok {
			return entry
		}
		entry := geoEntry{}
		if geo != nil {
			if name, code, _, ok := geo.Annotate(ip); ok {
				entry = geoEntry{code: code, name: name}
			}
		}
		geoMemo[ip] = entry
		return entry
	}

	// 24 hourly buckets, chronological, ending with the hour in progress.
	firstHour := now.UTC().Truncate(time.Hour).Add(-23 * time.Hour)
	timeline := make([]Bucket, 24)
	hourIPs := make([]map[string]struct{}, 24)
	for i := range timeline {
		t := firstHour.Add(time.Duration(i) * time.Hour)
		timeline[i] = Bucket{TS: t.UnixMilli(), Label: t.Format("15:04")}
		hourIPs[i] = map[string]struct{}{}
	}

	// 14 daily buckets, chronological, ending today (UTC).
	firstDay := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -13)
	daily := make([]Bucket, 14)
	dayIPs := make([]map[string]struct{}, 14)
	for i := range daily {
		t := firstDay.AddDate(0, 0, i)
		daily[i] = Bucket{TS: t.UnixMilli(), Label: t.Format("Jan 02")}
		dayIPs[i] = map[string]struct{}{}
	}

	heat := make([]int, 7*24)

	for _, e := range s.events {
		et := time.UnixMilli(e.TS).UTC()

		// Monday-first weekday, so the heatmap reads like a work week.
		dow := (int(et.Weekday()) + 6) % 7
		heat[dow*24+et.Hour()]++

		isAttempt := e.Type == "auth_attempt" || e.Type == "login_attempt"
		isSuccess := e.Type == "auth_success"

		if idx := int(et.Truncate(time.Hour).Sub(firstHour) / time.Hour); idx >= 0 && idx < len(timeline) {
			timeline[idx].Count++
			if isAttempt {
				timeline[idx].Attempts++
			}
			if isSuccess {
				timeline[idx].Attempts++
				timeline[idx].Accepted++
			}
			if e.RemoteIP != "" {
				hourIPs[idx][e.RemoteIP] = struct{}{}
			}
		}
		if idx := int(et.Truncate(24*time.Hour).Sub(firstDay) / (24 * time.Hour)); idx >= 0 && idx < len(daily) {
			daily[idx].Count++
			if isAttempt {
				daily[idx].Attempts++
			}
			if isSuccess {
				daily[idx].Attempts++
				daily[idx].Accepted++
			}
			if e.RemoteIP != "" {
				dayIPs[idx][e.RemoteIP] = struct{}{}
			}
		}

		if e.TS >= cutoff24 {
			stats.Last24h++
			if e.RemoteIP != "" {
				seenIPs24[e.RemoteIP] = struct{}{}
			}
		}
		if e.TS >= cutoff1h {
			stats.LastHour++
		}

		if e.Type != "" {
			typeCount[e.Type]++
		}
		if e.RemoteIP != "" {
			ipCount[e.RemoteIP]++
			seenIPs[e.RemoteIP] = struct{}{}
			entry := lookupGeo(e.RemoteIP)
			if e.CountryCode != "" {
				// The event was annotated when it was logged.
				entry = geoEntry{code: e.CountryCode, name: e.Country}
			}
			if entry.code != "" || entry.name != "" {
				key := entry.code
				if key == "" {
					key = entry.name
				}
				countryCount[key]++
				if entry.name != "" {
					countryName[key] = entry.name
				}
				if countryIPs[key] == nil {
					countryIPs[key] = map[string]struct{}{}
				}
				countryIPs[key][e.RemoteIP] = struct{}{}
			}
		}
		if e.LocalPort > 0 {
			portCount[fmt.Sprintf("%d/%s", e.LocalPort, e.Service)]++
		}
		if e.Command != "" {
			cmdCount[e.Command]++
		}

		switch e.Type {
		case "auth_success":
			stats.Accepted++
		case "authenticated":
			stats.ShellSessions++
		case "command", "exec":
			stats.Commands++
		}

		if e.Service != "" {
			agg := svcAggs[e.Service]
			if agg == nil {
				agg = &serviceAgg{ips: map[string]struct{}{}}
				svcAggs[e.Service] = agg
			}
			agg.events++
			if e.TS > agg.lastSeen {
				agg.lastSeen = e.TS
			}
			if agg.firstSeen == 0 || e.TS < agg.firstSeen {
				agg.firstSeen = e.TS
			}
			if e.LocalPort > 0 {
				agg.port = e.LocalPort
			}
			if e.RemoteIP != "" {
				agg.ips[e.RemoteIP] = struct{}{}
			}
			switch e.Type {
			case "auth_attempt":
				agg.authAttempt++
			case "login_attempt":
				agg.loginAttempt++
			case "auth_success":
				agg.authSuccess++
			case "command", "exec":
				agg.commands++
			}
		}

		if (isAttempt || isSuccess) && (e.Username != "" || e.Password != "") {
			key := e.Username + "\x00" + e.Password
			credCount[key]++
			credInfo[key] = CredCount{Username: e.Username, Password: e.Password, Count: credCount[key]}
			if e.Username != "" {
				userCount[e.Username]++
			}
			if e.Password != "" {
				passCount[e.Password]++
			}
		}

		if e.Details != nil {
			if u, ok := e.Details["url"].(string); ok && u != "" {
				pathCount[truncate(u, 120)]++
			}
			if v, ok := e.Details["version"].(string); ok && v != "" && e.Type == "client_version" {
				clientCount[truncate(v, 80)]++
			}
			if ua := headerValue(e.Details["headers"], "user-agent"); ua != "" {
				clientCount[truncate(ua, 80)]++
			}
		}
	}

	for i := range timeline {
		timeline[i].UniqueIPs = len(hourIPs[i])
	}
	for i := range daily {
		daily[i].UniqueIPs = len(dayIPs[i])
	}

	stats.Timeline = timeline
	stats.Daily = daily
	stats.Hourly = make([]KV, 0, len(timeline))
	for _, b := range timeline {
		stats.Hourly = append(stats.Hourly, KV{Key: b.Label, Count: b.Count})
		if b.Count > stats.PeakHourCount {
			stats.PeakHourCount = b.Count
			stats.PeakHour = b.Label
		}
	}

	max := 0
	for _, v := range heat {
		if v > max {
			max = v
		}
	}
	stats.Heatmap = Heatmap{Max: max, Grid: heat}

	stats.UniqueIPs = len(seenIPs)
	stats.UniqueIPs24h = len(seenIPs24)
	stats.EventsPerMin = float64(stats.LastHour) / 60

	stats.StartedAt = s.startedAt
	stats.UptimeMs = now.UnixMilli() - s.startedAt
	stats.EventsSinceStart = s.eventsSinceStart
	stats.TrafficSinceStart = s.trafficSinceStart
	stats.FirstEventSinceStart = s.firstSinceStart
	stats.FirstEventService = s.firstSinceService
	stats.TimeToFirstEventMs = -1
	if s.firstSinceStart > 0 {
		stats.TimeToFirstEventMs = s.firstSinceStart - s.startedAt
		if stats.TimeToFirstEventMs < 0 {
			stats.TimeToFirstEventMs = 0
		}
	}

	stats.TotalSessions = len(s.sessions)
	for _, sess := range s.sessions {
		if sess.ClosedAt == 0 {
			stats.ActiveSessions++
		}
	}

	svcCount := map[string]int{}
	stats.Services = make([]ServiceStat, 0, len(svcAggs))
	for name, agg := range svcAggs {
		svcCount[name] = agg.events
		stats.Attempts += agg.attempts()
		timeToFirst := int64(-1)
		firstSince := s.svcFirstSince[name]
		if firstSince > 0 {
			timeToFirst = firstSince - s.startedAt
			if timeToFirst < 0 {
				timeToFirst = 0
			}
		}
		stats.Services = append(stats.Services, ServiceStat{
			Service:          name,
			Port:             agg.port,
			Events:           agg.events,
			UniqueIPs:        len(agg.ips),
			Attempts:         agg.attempts(),
			Accepted:         agg.authSuccess,
			Commands:         agg.commands,
			FirstSeen:        agg.firstSeen,
			LastSeen:         agg.lastSeen,
			EventsSinceStart: s.svcEventsSince[name],
			FirstSinceStart:  firstSince,
			TimeToFirstMs:    timeToFirst,
		})
	}
	sort.Slice(stats.Services, func(i, j int) bool { return stats.Services[i].Events > stats.Services[j].Events })

	stats.Rejected = stats.Attempts - stats.Accepted
	if stats.Rejected < 0 {
		stats.Rejected = 0
	}

	stats.ByService = topK(svcCount, 20)
	stats.ByType = topK(typeCount, 20)
	stats.TopIPs = topK(ipCount, 15)
	for _, kv := range topK(countryCount, 20) {
		stats.TopCountries = append(stats.TopCountries, CountryCount{
			Code:      kv.Key,
			Name:      countryName[kv.Key],
			Count:     kv.Count,
			UniqueIPs: len(countryIPs[kv.Key]),
		})
	}
	stats.TopCommands = topK(cmdCount, 15)
	stats.TopUsernames = topK(userCount, 10)
	stats.TopPasswords = topK(passCount, 10)
	stats.TopPorts = topK(portCount, 15)
	stats.TopPaths = topK(pathCount, 10)
	stats.TopClients = topK(clientCount, 10)

	credList := make([]CredCount, 0, len(credInfo))
	for _, c := range credInfo {
		credList = append(credList, c)
	}
	sort.Slice(credList, func(i, j int) bool { return credList[i].Count > credList[j].Count })
	if len(credList) > 15 {
		credList = credList[:15]
	}
	stats.TopCreds = credList
	return stats
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// headerValue pulls one header out of the flattened header map an event
// carries. Live events hold map[string]string; events replayed from
// events.ndjson come back as map[string]any.
func headerValue(v any, name string) string {
	switch m := v.(type) {
	case map[string]string:
		for k, val := range m {
			if strings.EqualFold(k, name) {
				return val
			}
		}
	case map[string]any:
		for k, val := range m {
			if strings.EqualFold(k, name) {
				if s, ok := val.(string); ok {
					return s
				}
			}
		}
	}
	return ""
}

func topK(m map[string]int, k int) []KV {
	out := make([]KV, 0, len(m))
	for key, c := range m {
		out = append(out, KV{Key: key, Count: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if k > 0 && len(out) > k {
		out = out[:k]
	}
	return out
}

// Subscribe returns an unsubscribe func.
func (s *Store) Subscribe(fn Subscriber) func() {
	s.subMu.Lock()
	id := atomic.AddUint64(&s.subSeq, 1)
	s.subs[id] = fn
	s.subMu.Unlock()
	return func() {
		s.subMu.Lock()
		delete(s.subs, id)
		s.subMu.Unlock()
	}
}

func (s *Store) fanout(e Event) {
	s.subMu.RLock()
	subs := make([]Subscriber, 0, len(s.subs))
	for _, sub := range s.subs {
		subs = append(subs, sub)
	}
	s.subMu.RUnlock()
	for _, sub := range subs {
		func() {
			defer func() { _ = recover() }()
			sub(e)
		}()
	}
}

// RandID returns a random hex id of the requested byte length.
func RandID(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("id-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
