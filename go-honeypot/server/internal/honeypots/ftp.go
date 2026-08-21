package honeypots

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

func NewFTP(cfg config.Service, store *eventlog.Store) *TCP {
	banner := cfg.Banner
	if banner == "" {
		banner = "220 (vsFTPd 3.0.5)\r\n"
	}
	var t *TCP
	t = NewTCP("ftp", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		cfg := t.Cfg()
		if b := cfg.Banner; b != "" {
			banner = b
		}
		_, _ = conn.Write([]byte(banner))
		r := bufio.NewReader(conn)
		var username string
		loggedIn := false
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
				store.SetSessionUsername(sessionID, username)
				_, _ = conn.Write([]byte("331 Please specify the password.\r\n"))
			case "PASS":
				ok := shouldAccept(cfg.FakeAuth, username, arg)
				store.Log(eventlog.Event{
					Service: "ftp", Type: ternary(ok, "auth_success", "login_attempt"), SessionID: sessionID,
					RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
					Username: username, Password: arg,
					Details: map[string]any{"accepted": ok},
				})
				if ok {
					loggedIn = true
					_, _ = conn.Write([]byte("230 Login successful.\r\n"))
				} else {
					_, _ = conn.Write([]byte("530 Login incorrect.\r\n"))
				}
			case "SYST":
				_, _ = conn.Write([]byte("215 UNIX Type: L8\r\n"))
			case "PWD", "XPWD":
				if !loggedIn {
					_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				} else {
					_, _ = conn.Write([]byte("257 \"/\" is the current directory\r\n"))
				}
			case "LIST", "NLST":
				if !loggedIn {
					_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				} else {
					_, _ = conn.Write([]byte("150 Here comes the directory listing.\r\n226 Directory send OK.\r\n"))
				}
			case "CWD":
				if !loggedIn {
					_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				} else {
					_, _ = conn.Write([]byte("250 Directory successfully changed.\r\n"))
				}
			case "TYPE", "PASV", "EPSV", "PORT":
				if !loggedIn {
					_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				} else {
					_, _ = conn.Write([]byte("200 OK.\r\n"))
				}
			case "FEAT":
				_, _ = conn.Write([]byte("211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n"))
			case "AUTH":
				_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
			case "QUIT":
				_, _ = conn.Write([]byte("221 Goodbye.\r\n"))
				return
			default:
				if loggedIn {
					_, _ = conn.Write([]byte("502 Command not implemented.\r\n"))
				} else {
					_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				}
			}
			_ = ctx
		}
	})
	return t
}

func ternary(ok bool, a, b string) string {
	if ok {
		return a
	}
	return b
}

func splitFtpLine(line string) (string, string) {
	idx := strings.Index(line, " ")
	if idx < 0 {
		return line, ""
	}
	return line[:idx], line[idx+1:]
}
