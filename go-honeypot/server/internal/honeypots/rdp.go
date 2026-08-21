package honeypots

import (
	"context"
	"encoding/hex"
	"net"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

func NewRDP(cfg config.Service, store *eventlog.Store) *TCP {
	return NewTCP("rdp", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		buf := make([]byte, 0, 512)
		tmp := make([]byte, 512)
		for {
			n, err := conn.Read(tmp)
			if err != nil {
				return
			}
			buf = append(buf, tmp[:n]...)
			if len(buf) > 2048 {
				buf = buf[:2048]
			}
			logBuf := buf
			if len(logBuf) > 128 {
				logBuf = logBuf[:128]
			}
			store.Log(eventlog.Event{
				Service: "rdp", Type: "payload", SessionID: sessionID,
				RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
				Details: map[string]any{"hex": hex.EncodeToString(logBuf), "length": len(buf)},
			})
			if len(buf) >= 5 && buf[0] == 0x03 {
				// X.224 Connection Confirm advertising TLS
				resp := []byte{
					0x03, 0x00, 0x00, 0x13,
					0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
					0x02, 0x00, 0x08, 0x00,
					0x02, 0x00, 0x00, 0x00,
					0x00, 0x00,
				}
				_, _ = conn.Write(resp)
				buf = buf[:0]
			}
			_ = ctx
		}
	})
}
