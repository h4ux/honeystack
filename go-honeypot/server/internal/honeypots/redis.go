package honeypots

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/example/honeypot/internal/config"
	"github.com/example/honeypot/internal/eventlog"
)

func NewRedis(cfg config.Service, store *eventlog.Store) *TCP {
	return NewTCP("redis", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		var buf strings.Builder
		tmp := make([]byte, 512)
		for {
			n, err := conn.Read(tmp)
			if err != nil {
				return
			}
			buf.Write(tmp[:n])
			cmds, remainder := parseResp(buf.String())
			buf.Reset()
			buf.WriteString(remainder)
			for _, parts := range cmds {
				upper := ""
				if len(parts) > 0 {
					upper = strings.ToUpper(parts[0])
				}
				evt := eventlog.Event{
					Service: "redis", Type: "command", SessionID: sessionID,
					RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
					Command: strings.Join(parts, " "),
				}
				switch upper {
				case "AUTH":
					evt.Type = "login_attempt"
					if len(parts) > 2 {
						evt.Username = parts[1]
						evt.Password = parts[2]
					} else if len(parts) > 1 {
						evt.Username = "default"
						evt.Password = parts[1]
					}
					store.Log(evt)
					_, _ = conn.Write([]byte("-WRONGPASS invalid username-password pair or user is disabled.\r\n"))
				case "PING":
					store.Log(evt)
					_, _ = conn.Write([]byte("+PONG\r\n"))
				case "QUIT":
					store.Log(evt)
					_, _ = conn.Write([]byte("+OK\r\n"))
					return
				default:
					store.Log(evt)
					_, _ = conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
				}
			}
			_ = ctx
		}
	})
}

// parseResp parses one or more RESP arrays (or inline commands) from `s`.
func parseResp(s string) ([][]string, string) {
	var out [][]string
	i := 0
	for i < len(s) {
		if s[i] == '*' {
			nl := strings.Index(s[i:], "\r\n")
			if nl < 0 {
				break
			}
			count, err := strconv.Atoi(s[i+1 : i+nl])
			if err != nil {
				break
			}
			off := i + nl + 2
			parts := make([]string, 0, count)
			ok := true
			for n := 0; n < count; n++ {
				if off >= len(s) || s[off] != '$' {
					ok = false
					break
				}
				nl2 := strings.Index(s[off:], "\r\n")
				if nl2 < 0 {
					ok = false
					break
				}
				strLen, err := strconv.Atoi(s[off+1 : off+nl2])
				if err != nil {
					ok = false
					break
				}
				off += nl2 + 2
				if off+strLen+2 > len(s) {
					ok = false
					break
				}
				parts = append(parts, s[off:off+strLen])
				off += strLen + 2
			}
			if !ok {
				break
			}
			out = append(out, parts)
			i = off
		} else {
			nl := strings.Index(s[i:], "\r\n")
			if nl < 0 {
				break
			}
			line := s[i : i+nl]
			fields := strings.Fields(line)
			if len(fields) > 0 {
				out = append(out, fields)
			}
			i += nl + 2
		}
	}
	return out, s[i:]
}

var _ = errors.New
