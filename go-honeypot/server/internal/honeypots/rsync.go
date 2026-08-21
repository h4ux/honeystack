package honeypots

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

// NewRsync emulates an rsync daemon (port 873). Exposed rsync modules leak
// backups constantly, so scanners ask for the module list first and then try
// to authenticate against whatever they find.
func NewRsync(cfg config.Service, store *eventlog.Store) *TCP {
	var t *TCP
	t = NewTCP("rsync", cfg, store, func(_ context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		cfg := t.Cfg()
		greeting := cfg.Banner
		if greeting == "" {
			greeting = "@RSYNCD: 31.0\n"
		}
		_, _ = conn.Write([]byte(greeting))

		r := bufio.NewReader(conn)
		log := func(typ string, e eventlog.Event) {
			e.Service, e.Type, e.SessionID = "rsync", typ, sessionID
			e.RemoteIP, e.RemotePort, e.LocalPort = meta.RemoteIP, meta.RemotePort, meta.LocalPort
			store.Log(e)
		}

		// The client echoes its own @RSYNCD: <version> line first.
		hello, err := r.ReadString('\n')
		if err != nil {
			return
		}
		log("client_version", eventlog.Event{
			Command: strings.TrimSpace(hello),
			Details: map[string]any{"version": strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(hello), "@RSYNCD:"))},
		})

		// One module request per connection: rsyncd either lists modules and
		// exits, or challenges for auth and drops us on failure.
		{
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			request := strings.TrimSpace(line)
			log("command", eventlog.Event{
				Command: request,
				Details: map[string]any{"module": request},
			})

			switch request {
			case "", "#list":
				_, _ = conn.Write([]byte(rsyncModuleList()))
				_, _ = conn.Write([]byte("@RSYNCD: EXIT\n"))
				return
			default:
				// Any module request gets challenged, which is what makes the
				// scanner hand over a username and a challenge response.
				challenge := eventlog.RandID(8)
				_, _ = conn.Write([]byte("@RSYNCD: AUTHREQD " + challenge + "\n"))
				authLine, err := r.ReadString('\n')
				if err != nil {
					return
				}
				user, response := splitFtpLine(strings.TrimSpace(authLine))
				store.SetSessionUsername(sessionID, user)
				log("login_attempt", eventlog.Event{
					Username: user, Password: response,
					Details: map[string]any{
						"module": request, "challenge": challenge,
						"note": "rsync sends an MD4 challenge response, not the password",
					},
				})
				_, _ = conn.Write([]byte("@ERROR: auth failed on module " + request + "\n"))
				return
			}
		}
	})
	return t
}

func rsyncModuleList() string {
	modules := [][2]string{
		{"backup", "nightly server backups"},
		{"www", "web root"},
		{"data", "shared datasets"},
	}
	var b strings.Builder
	for _, m := range modules {
		b.WriteString(m[0])
		b.WriteString("\t")
		b.WriteString(m[1])
		b.WriteString("\n")
	}
	return b.String()
}
