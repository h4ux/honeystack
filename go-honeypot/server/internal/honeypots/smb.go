package honeypots

import (
	"context"
	"encoding/hex"
	"net"

	"github.com/example/honeypot/internal/config"
	"github.com/example/honeypot/internal/eventlog"
)

func NewSMB(cfg config.Service, store *eventlog.Store) *TCP {
	return NewTCP("smb", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		data := buf[:n]
		looksSMB := n >= 8 && data[4] == 0xfe && string(data[5:8]) == "SMB"
		logSlice := data
		if len(logSlice) > 128 {
			logSlice = logSlice[:128]
		}
		store.Log(eventlog.Event{
			Service: "smb", Type: "payload", SessionID: sessionID,
			RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
			Details: map[string]any{
				"hex":       hex.EncodeToString(logSlice),
				"length":    n,
				"looksSmb2": looksSMB,
			},
		})
		_ = ctx
	})
}
