package honeypots

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

// NewGeneric is a banner + byte-capture listener used for user-defined
// ports that are not one of the built-in protocol emulators.
func NewGeneric(name string, cfg config.Service, store *eventlog.Store) *TCP {
	banner := cfg.Banner
	kind := strings.ToLower(cfg.Kind)
	timeout := time.Duration(cfg.IdleTimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	maxCapture := cfg.CaptureBytes
	if maxCapture <= 0 {
		maxCapture = 8192
	}
	t := NewTCP(name, cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		if banner != "" {
			_, _ = conn.Write([]byte(banner))
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		total := 0
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					store.Log(eventlog.Event{
						Service: name, Type: "connection_closed", SessionID: sessionID,
						RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
						Details: map[string]any{"error": err.Error()},
					})
				}
				return
			}
			chunk := buf[:n]
			total += n
			preview := string(chunk)
			if len(preview) > 512 {
				preview = preview[:512]
			}
			store.Log(eventlog.Event{
				Service: name, Type: "payload", SessionID: sessionID,
				RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
				Command: strings.TrimSpace(preview),
				Details: map[string]any{"bytes": n, "kind": kind, "preview": preview},
			})
			if kind == "echo" {
				_, _ = conn.Write(chunk)
			}
			if total >= maxCapture {
				return
			}
			_ = ctx
		}
	})
	t.timeout = timeout
	return t
}

func NewGenericUDP(name string, cfg config.Service, store *eventlog.Store) *UDP {
	return NewUDP(name, cfg, store)
}

// UDPReply is what a protocol handler wants logged, plus the datagram to
// send back. A zero Type means "log nothing extra".
type UDPReply struct {
	Type     string
	Command  string
	Username string
	Password string
	Details  map[string]any
	Response []byte
}

// UDPHandler turns one inbound datagram into a logged event and a reply.
type UDPHandler func(payload []byte, meta ConnMeta) UDPReply

type UDP struct {
	name    string
	mu      sync.RWMutex
	cfg     config.Service
	store   *eventlog.Store
	conn    *net.UDPConn
	cancel  context.CancelFunc
	handler UDPHandler
}

func NewUDP(name string, cfg config.Service, store *eventlog.Store) *UDP {
	return &UDP{name: name, cfg: cfg, store: store}
}

// NewUDPProto is NewUDP with a protocol emulator attached.
func NewUDPProto(name string, cfg config.Service, store *eventlog.Store, h UDPHandler) *UDP {
	return &UDP{name: name, cfg: cfg, store: store, handler: h}
}

func (u *UDP) Name() string { return u.name }
func (u *UDP) Port() int {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.cfg.Port
}
func (u *UDP) UpdateConfig(cfg config.Service) {
	u.mu.Lock()
	u.cfg = cfg
	u.mu.Unlock()
}
func (u *UDP) Cfg() config.Service {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.cfg
}

func (u *UDP) Start() error {
	addr, err := net.ResolveUDPAddr("udp", ":"+strconv.Itoa(u.Port()))
	if err != nil {
		return err
	}
	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	u.conn = c
	ctx, cancel := context.WithCancel(context.Background())
	u.cancel = cancel
	go u.readLoop(ctx)
	return nil
}

func (u *UDP) Stop() error {
	if u.cancel != nil {
		u.cancel()
	}
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}

func (u *UDP) readLoop(ctx context.Context) {
	buf := make([]byte, 2048)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = u.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		remoteIP, remotePort := splitHostPort(addr.String())
		sessionID := eventlog.RandID(8)
		cfg := u.Cfg()
		meta := ConnMeta{RemoteIP: remoteIP, RemotePort: remotePort, LocalPort: cfg.Port}
		u.store.OpenSession(eventlog.Session{
			ID: sessionID, Service: u.name, RemoteIP: remoteIP, RemotePort: remotePort,
		})

		if u.handler != nil {
			// Copy the payload: buf is reused on the next read.
			payload := make([]byte, n)
			copy(payload, buf[:n])
			reply := u.callHandler(payload, meta, sessionID)
			if reply.Type != "" {
				if reply.Username != "" {
					u.store.SetSessionUsername(sessionID, reply.Username)
				}
				u.store.Log(eventlog.Event{
					Service: u.name, Type: reply.Type, SessionID: sessionID,
					RemoteIP: remoteIP, RemotePort: remotePort, LocalPort: cfg.Port,
					Username: reply.Username, Password: reply.Password,
					Command: reply.Command, Details: reply.Details,
				})
			}
			if len(reply.Response) > 0 {
				_, _ = u.conn.WriteToUDP(reply.Response, addr)
			}
			u.store.CloseSession(sessionID)
			continue
		}

		preview := string(buf[:n])
		if len(preview) > 512 {
			preview = preview[:512]
		}
		u.store.Log(eventlog.Event{
			Service: u.name, Type: "datagram", SessionID: sessionID,
			RemoteIP: remoteIP, RemotePort: remotePort, LocalPort: cfg.Port,
			Command: preview,
			Details: map[string]any{"bytes": n},
		})
		if cfg.Banner != "" {
			_, _ = u.conn.WriteToUDP([]byte(cfg.Banner), addr)
		}
		u.store.CloseSession(sessionID)
	}
}

// callHandler isolates a protocol emulator's panic to one datagram.
func (u *UDP) callHandler(payload []byte, meta ConnMeta, sessionID string) (reply UDPReply) {
	defer func() {
		if r := recover(); r != nil {
			u.store.Log(eventlog.Event{
				Service: u.name, Type: "handler_error", SessionID: sessionID,
				RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
				Details: map[string]any{"panic": fmt.Sprintf("%v", r)},
			})
			reply = UDPReply{}
		}
	}()
	return u.handler(payload, meta)
}
