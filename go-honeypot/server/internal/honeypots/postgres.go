package honeypots

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

func NewPostgres(cfg config.Service, store *eventlog.Store) *TCP {
	return NewTCP("postgres", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 512)
		for len(buf) < 8192 {
			n, err := conn.Read(tmp)
			if err != nil {
				return
			}
			buf = append(buf, tmp[:n]...)
			if len(buf) < 8 {
				continue
			}
			if binary.BigEndian.Uint32(buf[0:4]) == 8 && binary.BigEndian.Uint32(buf[4:8]) == 80877103 {
				_, _ = conn.Write([]byte("N"))
				buf = buf[8:]
				continue
			}
			pkgLen := int(binary.BigEndian.Uint32(buf[0:4]))
			if len(buf) < pkgLen {
				continue
			}
			payload := buf[4:pkgLen]
			if len(payload) < 4 {
				return
			}
			if binary.BigEndian.Uint32(payload[0:4]) == 196608 {
				params := parseStartupParams(payload[4:])
				store.Log(eventlog.Event{
					Service: "postgres", Type: "login_attempt", SessionID: sessionID,
					RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
					Username: params["user"],
					Details:  map[string]any{"params": params},
				})
				user := params["user"]
				if user == "" {
					user = "unknown"
				}
				_, _ = conn.Write(pgErrorPacket("FATAL", "28P01", `password authentication failed for user "`+user+`"`))
			}
			return
		}
		_ = ctx
	})
}

func parseStartupParams(p []byte) map[string]string {
	out := map[string]string{}
	off := 0
	for off < len(p) {
		kEnd := bytes.IndexByte(p[off:], 0)
		if kEnd < 0 {
			break
		}
		key := string(p[off : off+kEnd])
		off += kEnd + 1
		if key == "" || off >= len(p) {
			break
		}
		vEnd := bytes.IndexByte(p[off:], 0)
		if vEnd < 0 {
			break
		}
		value := string(p[off : off+vEnd])
		off += vEnd + 1
		out[key] = value
	}
	return out
}

func pgErrorPacket(severity, code, message string) []byte {
	var body bytes.Buffer
	body.WriteByte('S')
	body.WriteString(severity)
	body.WriteByte(0)
	body.WriteByte('C')
	body.WriteString(code)
	body.WriteByte(0)
	body.WriteByte('M')
	body.WriteString(message)
	body.WriteByte(0)
	body.WriteByte(0)
	var out bytes.Buffer
	out.WriteByte('E')
	_ = binary.Write(&out, binary.BigEndian, uint32(body.Len()+4))
	_, _ = out.Write(body.Bytes())
	return out.Bytes()
}
