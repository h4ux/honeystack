package honeypots

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"net"
	"strings"

	"github.com/example/honeypot/internal/config"
	"github.com/example/honeypot/internal/eventlog"
)

func NewVNC(cfg config.Service, store *eventlog.Store) *TCP {
	banner := cfg.Banner
	if banner == "" {
		banner = "RFB 003.008\n"
	}
	return NewTCP("vnc", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		_, _ = conn.Write([]byte(banner))
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		store.Log(eventlog.Event{
			Service: "vnc", Type: "client_version", SessionID: sessionID,
			RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
			Details: map[string]any{"version": strings.TrimSpace(string(buf[:n]))},
		})
		// Offer VNC Authentication only
		_, _ = conn.Write([]byte{0x01, 0x02})
		sel := make([]byte, 1)
		if _, err := conn.Read(sel); err != nil || sel[0] != 0x02 {
			return
		}
		challenge := make([]byte, 16)
		_, _ = cryptorand.Read(challenge)
		_, _ = conn.Write(challenge)
		resp := make([]byte, 16)
		if _, err := conn.Read(resp); err != nil {
			return
		}
		store.Log(eventlog.Event{
			Service: "vnc", Type: "auth_attempt", SessionID: sessionID,
			RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
			Details: map[string]any{
				"challenge": hex.EncodeToString(challenge),
				"response":  hex.EncodeToString(resp),
			},
		})
		_, _ = conn.Write([]byte{0x00, 0x00, 0x00, 0x01})
		_ = ctx
	})
}
