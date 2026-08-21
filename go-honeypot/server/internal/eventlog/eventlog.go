// Package eventlog stores honeypot events in memory (ring buffer) and
// appends every event to a newline-delimited JSON file for persistence.
package eventlog

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	Events       []Event `json:"events,omitempty"`
}

// Stats is the aggregate view the dashboard renders. Counters are over
// everything still retained (memory ring + whatever was replayed from
// events.ndjson), so they grow until the ring wraps.
type Stats struct {
	Total          int     `json:"total"`
	Last24h        int     `json:"last24h"`
	LastHour       int     `json:"lastHour"`
	UniqueIPs      int     `json:"uniqueIps"`
	UniqueIPs24h   int     `json:"uniqueIps24h"`
	ActiveSessions int     `json:"activeSessions"`
	TotalSessions  int     `json:"totalSessions"`
	ShellSessions  int     `json:"shellSessions"`
	Commands       int     `json:"commands"`
	Attempts       int     `json:"attempts"`
	Accepted       int     `json:"accepted"`
	Rejected       int     `json:"rejected"`
	FirstEventTS   int64   `json:"firstEventTs"`
	LastEventTS    int64   `json:"lastEventTs"`
	EventsPerMin   float64 `json:"eventsPerMin"`
	PeakHour       string  `json:"peakHour"`
	PeakHourCount  int     `json:"peakHourCount"`

	ByService []KV `json:"byService"`
	ByType    []KV `json:"byType"`
	// Hourly is the last 24 hours in chronological order (one bucket per
	// hour, UTC) — not a top-N list, so it can be plotted as a series.
	Hourly   []KV     `json:"hourly"`
	Timeline []Bucket `json:"timeline"`
	Daily    []Bucket `json:"daily"`
	Heatmap  Heatmap  `json:"heatmap"`

	TopIPs       []KV          `json:"topIps"`
	TopCreds     []CredCount   `json:"topCreds"`
	TopCommands  []KV          `json:"topCommands"`
	TopUsernames []KV          `json:"topUsernames"`
	TopPasswords []KV          `json:"topPasswords"`
	TopPorts     []KV          `json:"topPorts"`
	TopPaths     []KV          `json:"topPaths"`
	TopClients   []KV          `json:"topClients"`
	Services     []ServiceStat `json:"serviceStats"`
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

// ServiceStat is the per-listener breakdown behind the service table.
type ServiceStat struct {
	Service   string `json:"service"`
	Port      int    `json:"port"`
	Events    int    `json:"events"`
	UniqueIPs int    `json:"uniqueIps"`
	Attempts  int    `json:"attempts"`
	Accepted  int    `json:"accepted"`
	Commands  int    `json:"commands"`
	LastSeen  int64  `json:"lastSeen"`
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
}

func New(logPath string, maxRows int) (*Store, error) {
	if maxRows <= 0 {
		maxRows = 200000
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	s := &Store{
		max:      maxRows,
		sessions: map[string]*Session{},
		file:     f,
		writer:   bufio.NewWriter(f),
		flushCh:  make(chan struct{}, 1),
		closeCh:  make(chan struct{}),
		subs:     map[uint64]Subscriber{},
	}
	// Rehydrate from the NDJSON log so a dashboard that connects after a
	// restart still sees history, not just events since the daemon booted.
	if err := s.loadFromDisk(logPath, maxRows); err != nil {
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

	ring := make([]Event, 0, 4096)
	sc := bufio.NewScanner(f)
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
		log.Printf("[eventlog] replayed %d events from %s", n, logPath)
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

func (s *Store) Close() {
	close(s.closeCh)
}

// Log appends an event, notifies subscribers, and returns the stored copy.
func (s *Store) Log(e Event) Event {
	if e.TS == 0 {
		e.TS = time.Now().UnixMilli()
	}
	s.mu.Lock()
	s.nextID++
	e.ID = s.nextID
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
	_, _ = s.writer.Write(b)
	_, _ = s.writer.Write([]byte("\n"))
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
	s.mu.Unlock()
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

func (s *Store) Sessions(service string, limit int) []Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		if service != "" && sess.Service != service {
			continue
		}
		copy := *sess
		copy.Events = nil
		out = append(out, copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OpenedAt > out[j].OpenedAt })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
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

	s.mu.RLock()
	evts := make([]Event, 0, 32)
	for _, e := range s.events {
		if e.SessionID == id {
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

func (s *Store) Stats() Stats {
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
		stats.Services = append(stats.Services, ServiceStat{
			Service:   name,
			Port:      agg.port,
			Events:    agg.events,
			UniqueIPs: len(agg.ips),
			Attempts:  agg.attempts(),
			Accepted:  agg.authSuccess,
			Commands:  agg.commands,
			LastSeen:  agg.lastSeen,
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
