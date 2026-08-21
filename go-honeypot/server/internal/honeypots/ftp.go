package honeypots

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/example/honeypot/internal/config"
	"github.com/example/honeypot/internal/eventlog"
)

func NewFTP(cfg config.Service, store *eventlog.Store) *TCP {
	banner := cfg.Banner
	if banner == "" {
		banner = "220 (vsFTPd 3.0.5)\r\n"
	}
	return NewTCP("ftp", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		_, _ = conn.Write([]byte(banner))
		r := bufio.NewReader(conn)
		var username string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			cmd, arg := splitFtpLine(line)
			upper := strings.ToUpper(cmd)
			store.Log(eventlog.Event{
				Service: "ftp", Type: "command", SessionID: sessionID,
				RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
				Command: line, Username: username,
				Details: map[string]any{"cmd": upper, "arg": arg},
			})
			switch upper {
			case "USER":
				username = arg
				_, _ = conn.Write([]byte("331 Please specify the password.\r\n"))
			case "PASS":
				store.Log(eventlog.Event{
					Service: "ftp", Type: "login_attempt", SessionID: sessionID,
					RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
					Username: username, Password: arg,
				})
				_, _ = conn.Write([]byte("530 Login incorrect.\r\n"))
			case "SYST":
				_, _ = conn.Write([]byte("215 UNIX Type: L8\r\n"))
			case "FEAT":
				_, _ = conn.Write([]byte("211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n"))
			case "AUTH":
				_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
			case "QUIT":
				_, _ = conn.Write([]byte("221 Goodbye.\r\n"))
				return
			default:
				_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
			}
			_ = ctx
		}
	})
}

func splitFtpLine(line string) (string, string) {
	idx := strings.Index(line, " ")
	if idx < 0 {
		return line, ""
	}
	return line[:idx], line[idx+1:]
}
