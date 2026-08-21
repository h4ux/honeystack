package honeypots

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
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

type UDP struct {
	name   string
	cfg    config.Service
	store  *eventlog.Store
	conn   *net.UDPConn
	cancel context.CancelFunc
}

func NewUDP(name string, cfg config.Service, store *eventlog.Store) *UDP {
	return &UDP{name: name, cfg: cfg, store: store}
}

func (u *UDP) Name() string { return u.name }
func (u *UDP) Port() int    { return u.cfg.Port }
func (u *UDP) UpdateConfig(cfg config.Service) {
	u.cfg = cfg
}

func (u *UDP) Start() error {
	addr, err := net.ResolveUDPAddr("udp", ":"+strconv.Itoa(u.cfg.Port))
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
		u.store.OpenSession(eventlog.Session{
			ID: sessionID, Service: u.name, RemoteIP: remoteIP, RemotePort: remotePort,
		})
		preview := string(buf[:n])
		if len(preview) > 512 {
			preview = preview[:512]
		}
		u.store.Log(eventlog.Event{
			Service: u.name, Type: "datagram", SessionID: sessionID,
			RemoteIP: remoteIP, RemotePort: remotePort, LocalPort: u.cfg.Port,
			Command: preview,
			Details: map[string]any{"bytes": n},
		})
		if u.cfg.Banner != "" {
			_, _ = u.conn.WriteToUDP([]byte(u.cfg.Banner), addr)
		}
		u.store.CloseSession(sessionID)
	}
}
