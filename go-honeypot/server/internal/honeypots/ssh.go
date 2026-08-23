package honeypots

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	gliderssh "github.com/gliderlabs/ssh"
	xssh "golang.org/x/crypto/ssh"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

type SSH struct {
	cfg         config.Service
	store       *eventlog.Store
	server      *gliderssh.Server
	listener    net.Listener
	hostKeyPath string

	mu   sync.Mutex
	done chan struct{}
}

func NewSSH(cfg config.Service, store *eventlog.Store, hostKeyPath string) (*SSH, error) {
	return &SSH{cfg: cfg, store: store, hostKeyPath: hostKeyPath}, nil
}

func (h *SSH) Name() string { return "ssh" }
func (h *SSH) Port() int    { return h.cfg.Port }

func (h *SSH) UpdateConfig(cfg config.Service) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cfg = cfg
}

func (h *SSH) currentCfg() config.Service {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cfg
}

func (h *SSH) Start() error {
	if err := os.MkdirAll(filepath.Dir(h.hostKeyPath), 0o755); err != nil {
		return err
	}
	signer, err := ensureHostKey(h.hostKeyPath)
	if err != nil {
		return fmt.Errorf("host key: %w", err)
	}

	addr := ":" + strconv.Itoa(h.cfg.Port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	l = Guard(l)
	h.listener = l

	h.done = make(chan struct{})

	srv := &gliderssh.Server{
		Version:          strings.TrimPrefix(firstNonEmpty(h.cfg.Banner, "SSH-2.0-OpenSSH_8.9p1"), "SSH-2.0-"),
		Handler:          h.handleSession,
		PasswordHandler:  h.handlePassword,
		PublicKeyHandler: h.handlePublicKey,
	}
	srv.AddHostKey(signer)
	h.server = srv

	go func() {
		defer close(h.done)
		if err := srv.Serve(l); err != nil && !errors.Is(err, gliderssh.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			h.store.Log(eventlog.Event{Service: "ssh", Type: "server_error", Details: map[string]any{"error": err.Error()}})
		}
	}()
	return nil
}

func (h *SSH) Stop() error {
	if h.server != nil {
		_ = h.server.Close()
	}
	if h.listener != nil {
		_ = h.listener.Close()
	}
	if h.done != nil {
		<-h.done
	}
	return nil
}

// -------- auth handlers --------

func (h *SSH) handlePassword(ctx gliderssh.Context, password string) bool {
	cfg := h.currentCfg()
	remoteIP, remotePort := splitHostPort(ctx.RemoteAddr().String())
	sessionID := getOrInitSessionID(ctx, h.store, cfg.Port, remoteIP, remotePort)

	h.store.Log(eventlog.Event{
		Service: "ssh", Type: "auth_attempt", SessionID: sessionID,
		RemoteIP: remoteIP, RemotePort: remotePort, LocalPort: cfg.Port,
		Username: ctx.User(), Password: password,
		Details: map[string]any{"method": "password"},
	})

	ok := shouldAccept(cfg.FakeAuth, ctx.User(), password)
	if ok {
		h.store.SetSessionUsername(sessionID, ctx.User())
		h.store.Log(eventlog.Event{
			Service: "ssh", Type: "auth_success", SessionID: sessionID,
			RemoteIP: remoteIP, RemotePort: remotePort, LocalPort: cfg.Port,
			Username: ctx.User(), Password: password,
			Details: map[string]any{"method": "password"},
		})
	}
	return ok
}

func (h *SSH) handlePublicKey(ctx gliderssh.Context, key gliderssh.PublicKey) bool {
	cfg := h.currentCfg()
	remoteIP, remotePort := splitHostPort(ctx.RemoteAddr().String())
	sessionID := getOrInitSessionID(ctx, h.store, cfg.Port, remoteIP, remotePort)
	fp := xssh.FingerprintSHA256(key)
	h.store.Log(eventlog.Event{
		Service: "ssh", Type: "auth_attempt", SessionID: sessionID,
		RemoteIP: remoteIP, RemotePort: remotePort, LocalPort: cfg.Port,
		Username: ctx.User(),
		Details:  map[string]any{"method": "publickey", "type": key.Type(), "fingerprint": fp},
	})
	return false
}

// -------- session handler --------

func (h *SSH) handleSession(sess gliderssh.Session) {
	cfg := h.currentCfg()
	remoteIP, remotePort := splitHostPort(sess.RemoteAddr().String())
	sessionID := getOrInitSessionID(sess.Context(), h.store, cfg.Port, remoteIP, remotePort)

	h.store.SetSessionUsername(sessionID, sess.User())
	h.store.Log(eventlog.Event{
		Service: "ssh", Type: "authenticated", SessionID: sessionID,
		RemoteIP: remoteIP, RemotePort: remotePort, LocalPort: cfg.Port,
		Username: sess.User(),
	})
	defer h.store.CloseSession(sessionID)

	if raw := sess.RawCommand(); raw != "" {
		h.store.Log(eventlog.Event{
			Service: "ssh", Type: "exec", SessionID: sessionID,
			RemoteIP: remoteIP, RemotePort: remotePort, LocalPort: cfg.Port,
			Username: sess.User(), Command: raw,
		})
		env := newShellEnv(shellHostname(cfg), sess.User())
		res := runShellCommand(raw, env)
		if res.output != "" {
			_, _ = io.WriteString(sess, res.output)
		}
		_ = sess.Exit(0)
		return
	}

	ptyReq, winCh, isPty := sess.Pty()
	env := newShellEnv(shellHostname(cfg), sess.User())
	_ = ptyReq
	writeCRLF := func(s string) { _, _ = io.WriteString(sess, strings.ReplaceAll(s, "\n", "\r\n")) }

	if cfg.Shell != nil && cfg.Shell.Motd != "" {
		writeCRLF(cfg.Shell.Motd + "\n")
	}
	writeCRLF(env.prompt())

	if !isPty {
		writeCRLF("This service allocates a pty.\r\n")
		_ = sess.Exit(0)
		return
	}

	go func() {
		for range winCh {
			// consume resize events
		}
	}()

	buf := make([]byte, 0, 256)
	oneByte := make([]byte, 1)
	for {
		n, err := sess.Read(oneByte)
		if err != nil || n == 0 {
			return
		}
		ch := oneByte[0]
		switch {
		case ch == '\r' || ch == '\n':
			writeCRLF("\n")
			command := string(buf)
			buf = buf[:0]
			if strings.TrimSpace(command) != "" {
				h.store.Log(eventlog.Event{
					Service: "ssh", Type: "command", SessionID: sessionID,
					RemoteIP: remoteIP, RemotePort: remotePort, LocalPort: cfg.Port,
					Username: sess.User(), Command: command,
				})
				res := runShellCommand(command, env)
				if res.exit {
					writeCRLF("logout\r\n")
					_ = sess.Exit(0)
					return
				}
				if res.output != "" {
					writeCRLF(res.output)
				}
			}
			writeCRLF(env.prompt())
		case ch == 0x7f || ch == 0x08:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				_, _ = io.WriteString(sess, "\b \b")
			}
		case ch == 0x03: // Ctrl-C
			writeCRLF("^C\r\n")
			buf = buf[:0]
			writeCRLF(env.prompt())
		case ch == 0x04: // Ctrl-D on empty line
			if len(buf) == 0 {
				writeCRLF("logout\r\n")
				_ = sess.Exit(0)
				return
			}
		case ch >= 32 && ch < 127:
			buf = append(buf, ch)
			_, _ = sess.Write([]byte{ch})
		}
	}
}

// -------- helpers --------

func shellHostname(cfg config.Service) string {
	if cfg.Shell != nil && cfg.Shell.Hostname != "" {
		return cfg.Shell.Hostname
	}
	if cfg.Hostname != "" {
		return cfg.Hostname
	}
	return "ubuntu"
}

type ctxKey string

const sessionIDKey ctxKey = "sessionID"

func getOrInitSessionID(ctx context.Context, store *eventlog.Store, localPort int, remoteIP string, remotePort int) string {
	if v := ctx.Value(sessionIDKey); v != nil {
		if id, ok := v.(string); ok {
			return id
		}
	}
	id := eventlog.RandID(8)
	if setter, ok := ctx.(interface{ SetValue(key, value any) }); ok {
		setter.SetValue(sessionIDKey, id)
	}
	store.OpenSession(eventlog.Session{
		ID: id, Service: "ssh",
		RemoteIP: remoteIP, RemotePort: remotePort,
	})
	store.Log(eventlog.Event{
		Service: "ssh", Type: "connection", SessionID: id,
		RemoteIP: remoteIP, RemotePort: remotePort, LocalPort: localPort,
	})
	return id
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// -------- host key --------

func ensureHostKey(path string) (xssh.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		if s, err := xssh.ParsePrivateKey(b); err == nil {
			return s, nil
		}
	}
	_, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := xssh.MarshalPrivateKey(priv, "honeypot")
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return xssh.ParsePrivateKey(pemBytes)
}
