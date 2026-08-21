package honeypots

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/example/honeypot/internal/config"
	"github.com/example/honeypot/internal/eventlog"
)

type ConnHandler func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta)

type ConnMeta struct {
	RemoteIP   string
	RemotePort int
	LocalPort  int
}

type TCP struct {
	name    string
	cfg     config.Service
	store   *eventlog.Store
	handler ConnHandler
	timeout time.Duration

	mu       sync.Mutex
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func NewTCP(name string, cfg config.Service, store *eventlog.Store, handler ConnHandler) *TCP {
	return &TCP{
		name:    name,
		cfg:     cfg,
		store:   store,
		handler: handler,
		timeout: 60 * time.Second,
	}
}

func (t *TCP) Name() string { return t.name }
func (t *TCP) Port() int    { return t.cfg.Port }

func (t *TCP) UpdateConfig(cfg config.Service) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cfg = cfg
}

func (t *TCP) Cfg() config.Service {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cfg
}

func (t *TCP) Start() error {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(t.cfg.Port))
	if err != nil {
		return err
	}
	t.listener = l
	t.ctx, t.cancel = context.WithCancel(context.Background())
	t.wg.Add(1)
	go t.accept()
	return nil
}

func (t *TCP) Stop() error {
	if t.cancel != nil {
		t.cancel()
	}
	if t.listener != nil {
		_ = t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *TCP) accept() {
	defer t.wg.Done()
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || t.ctx.Err() != nil {
				return
			}
			continue
		}
		t.wg.Add(1)
		go t.handle(conn)
	}
}

func (t *TCP) handle(c net.Conn) {
	defer t.wg.Done()
	defer c.Close()

	sessionID := eventlog.RandID(8)
	remoteIP, remotePort := splitHostPort(c.RemoteAddr().String())
	meta := ConnMeta{RemoteIP: remoteIP, RemotePort: remotePort, LocalPort: t.cfg.Port}

	t.store.Log(eventlog.Event{
		Service: t.name, Type: "connection",
		RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
		SessionID: sessionID,
	})

	_ = c.SetDeadline(time.Now().Add(t.timeout))
	ctx, cancel := context.WithCancel(t.ctx)
	defer cancel()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.store.Log(eventlog.Event{
					Service: t.name, Type: "handler_error",
					SessionID: sessionID,
					RemoteIP:  meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
					Details: map[string]any{"panic": fmt.Sprintf("%v", r)},
				})
			}
		}()
		t.handler(ctx, c, sessionID, meta)
	}()

	t.store.Log(eventlog.Event{
		Service: t.name, Type: "connection_closed",
		SessionID: sessionID,
		RemoteIP:  meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
	})
}

func splitHostPort(addr string) (string, int) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	host = strings.TrimPrefix(host, "::ffff:")
	p, _ := strconv.Atoi(port)
	return host, p
}
