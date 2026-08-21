package honeypots

import (
	"context"
	"io"
	"net"
	"strings"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

func NewTelnet(cfg config.Service, store *eventlog.Store) *TCP {
	banner := cfg.Banner
	if banner == "" {
		banner = "\r\nUbuntu 22.04 LTS\r\nlogin: "
	}
	var t *TCP
	t = NewTCP("telnet", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		cfg := t.Cfg()
		if b := cfg.Banner; b != "" {
			banner = b
		}
		_, _ = conn.Write([]byte{0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03})
		_, _ = conn.Write([]byte(banner))

		stage := "user"
		var username string
		var buf []byte
		attempts := 0
		lastCR := false
		readBuf := make([]byte, 512)
		write := func(s string) { _, _ = io.WriteString(conn, s) }
		for {
			n, err := conn.Read(readBuf)
			if err != nil {
				return
			}
			data := stripTelnet(readBuf[:n])
			for _, ch := range data {
				// Clients send CR LF; without this the LF submits a second,
				// empty line and (with fake auth on) logs the peer straight in.
				if ch == '\n' && lastCR {
					lastCR = false
					continue
				}
				lastCR = ch == '\r'
				if ch == '\r' || ch == '\n' {
					if len(buf) == 0 && stage == "user" {
						continue
					}
					if stage == "user" {
						username = string(buf)
						buf = buf[:0]
						store.SetSessionUsername(sessionID, username)
						write("\r\nPassword: ")
						stage = "pass"
					} else if stage == "pass" {
						password := string(buf)
						buf = buf[:0]
						attempts++
						ok := shouldAccept(cfg.FakeAuth, username, password)
						store.Log(eventlog.Event{
							Service: "telnet", Type: ternary(ok, "auth_success", "login_attempt"), SessionID: sessionID,
							RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
							Username: username, Password: password,
							Details: map[string]any{"accepted": ok, "attempt": attempts},
						})
						if ok {
							env := newShellEnv(shellHostname(cfg), username)
							write("\r\n")
							if cfg.Shell != nil && cfg.Shell.Motd != "" {
								write(strings.ReplaceAll(cfg.Shell.Motd, "\n", "\r\n") + "\r\n")
							}
							write(env.prompt())
							stage = "shell"
							continue
						}
						if attempts >= 3 {
							write("\r\nLogin incorrect. Too many failures.\r\n")
							return
						}
						write("\r\nLogin incorrect\r\nlogin: ")
						stage = "user"
					} else if stage == "shell" {
						command := string(buf)
						buf = buf[:0]
						write("\r\n")
						if strings.TrimSpace(command) != "" {
							store.Log(eventlog.Event{
								Service: "telnet", Type: "command", SessionID: sessionID,
								RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
								Username: username, Command: command,
							})
							env := newShellEnv(shellHostname(cfg), username)
							res := runShellCommand(command, env)
							if res.exit {
								write("logout\r\n")
								return
							}
							if res.output != "" {
								write(strings.ReplaceAll(res.output, "\n", "\r\n"))
							}
						}
						env := newShellEnv(shellHostname(cfg), username)
						write(env.prompt())
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
	return t
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
