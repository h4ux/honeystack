package honeypots

import (
	"context"
	"net"

	"github.com/example/honeypot/internal/config"
	"github.com/example/honeypot/internal/eventlog"
)

func NewTelnet(cfg config.Service, store *eventlog.Store) *TCP {
	banner := cfg.Banner
	if banner == "" {
		banner = "\r\nUbuntu 22.04 LTS\r\nlogin: "
	}
	return NewTCP("telnet", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		// Negotiate WILL ECHO, WILL SUPPRESS-GA
		_, _ = conn.Write([]byte{0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03})
		_, _ = conn.Write([]byte(banner))

		stage := "user"
		var username string
		var buf []byte
		attempts := 0
		readBuf := make([]byte, 512)
		for {
			n, err := conn.Read(readBuf)
			if err != nil {
				return
			}
			data := stripTelnet(readBuf[:n])
			for _, ch := range data {
				if ch == '\r' || ch == '\n' {
					if len(buf) == 0 && stage == "user" {
						continue
					}
					if stage == "user" {
						username = string(buf)
						buf = buf[:0]
						_, _ = conn.Write([]byte("\r\nPassword: "))
						stage = "pass"
					} else {
						password := string(buf)
						buf = buf[:0]
						attempts++
						store.Log(eventlog.Event{
							Service: "telnet", Type: "login_attempt", SessionID: sessionID,
							RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
							Username: username, Password: password,
						})
						if attempts >= 3 {
							_, _ = conn.Write([]byte("\r\nLogin incorrect. Too many failures.\r\n"))
							return
						}
						_, _ = conn.Write([]byte("\r\nLogin incorrect\r\nlogin: "))
						stage = "user"
					}
				} else if ch == 0x7f || ch == 0x08 {
					if len(buf) > 0 {
						buf = buf[:len(buf)-1]
					}
				} else if ch >= 0x20 && ch < 0x7f {
					buf = append(buf, ch)
				}
			}
			_ = ctx
		}
	})
}

func stripTelnet(in []byte) []byte {
	out := make([]byte, 0, len(in))
	i := 0
	for i < len(in) {
		if in[i] == 0xff {
			if i+1 >= len(in) {
				break
			}
			cmd := in[i+1]
			switch {
			case cmd == 0xff:
				out = append(out, 0xff)
				i += 2
			case cmd >= 0xfb && cmd <= 0xfe:
				i += 3
			case cmd == 0xfa:
				i += 2
				for i < len(in) && in[i] != 0xf0 {
					i++
				}
				i++
			default:
				i += 2
			}
		} else {
			out = append(out, in[i])
			i++
		}
	}
	return out
}
