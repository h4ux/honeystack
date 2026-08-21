// Package eventlog stores honeypot events in memory (ring buffer) and
// appends every event to a newline-delimited JSON file for persistence.
package eventlog

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

type Stats struct {
	Total          int         `json:"total"`
	Last24h        int         `json:"last24h"`
	UniqueIPs      int         `json:"uniqueIps"`
	ActiveSessions int         `json:"activeSessions"`
	ByService      []KV        `json:"byService"`
	TopIPs         []KV        `json:"topIps"`
	TopCreds       []CredCount `json:"topCreds"`
	TopCommands    []KV        `json:"topCommands"`
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
	go s.flusher()
	return s, nil
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
	Limit     int
}

func (s *Store) Events(f EventFilter) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
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
		out = append(out, e)
	}
	// reverse
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cutoff := time.Now().Add(-24 * time.Hour).UnixMilli()
	stats := Stats{Total: len(s.events)}
	svcCount := map[string]int{}
	ipCount := map[string]int{}
	credCount := map[string]int{}
	credInfo := map[string]CredCount{}
	cmdCount := map[string]int{}
	seenIPs := map[string]struct{}{}
	for _, e := range s.events {
		if e.TS >= cutoff {
			stats.Last24h++
		}
		if e.Service != "" {
			svcCount[e.Service]++
		}
		if e.RemoteIP != "" {
			ipCount[e.RemoteIP]++
			seenIPs[e.RemoteIP] = struct{}{}
		}
		if (e.Type == "auth_attempt" || e.Type == "login_attempt") && e.Username != "" {
			key := e.Username + "\x00" + e.Password
			credCount[key]++
			credInfo[key] = CredCount{Username: e.Username, Password: e.Password, Count: credCount[key]}
		}
		if e.Command != "" {
			cmdCount[e.Command]++
		}
	}
	stats.UniqueIPs = len(seenIPs)
	for _, sess := range s.sessions {
		if sess.ClosedAt == 0 {
			stats.ActiveSessions++
		}
	}
	stats.ByService = topK(svcCount, 20)
	stats.TopIPs = topK(ipCount, 10)
	stats.TopCommands = topK(cmdCount, 15)
	credList := make([]CredCount, 0, len(credInfo))
	for _, c := range credInfo {
		credList = append(credList, c)
	}
	sort.Slice(credList, func(i, j int) bool { return credList[i].Count > credList[j].Count })
	if len(credList) > 10 {
		credList = credList[:10]
	}
	stats.TopCreds = credList
	return stats
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
