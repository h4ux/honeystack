package honeypots

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

// Mail honeypots: SMTP, IMAP and POP3. All three are line based and all
// three are scanned mainly for credentials (and, for SMTP, for an open
// relay), so they share the same credential-capture shape.

func NewSMTP(cfg config.Service, store *eventlog.Store) *TCP {
	var t *TCP
	t = NewTCP("smtp", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		cfg := t.Cfg()
		host := cfg.Hostname
		if host == "" {
			host = "mail.web-prod-01.local"
		}
		banner := cfg.Banner
		if banner == "" {
			banner = fmt.Sprintf("220 %s ESMTP Postfix (Ubuntu)\r\n", host)
		}
		_, _ = conn.Write([]byte(banner))

		r := bufio.NewReader(conn)
		log := func(typ string, e eventlog.Event) {
			e.Service, e.Type, e.SessionID = "smtp", typ, sessionID
			e.RemoteIP, e.RemotePort, e.LocalPort = meta.RemoteIP, meta.RemotePort, meta.LocalPort
			store.Log(e)
		}

		var username, mailFrom string
		var recipients []string
		authed := false
		inData := false
		var body strings.Builder

		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")

			// Inside DATA everything is message content until a lone dot.
			if inData {
				if line == "." {
					inData = false
					log("mail_relay", eventlog.Event{
						Username: username,
						Command:  fmt.Sprintf("DATA %d bytes to %s", body.Len(), strings.Join(recipients, ",")),
						Details: map[string]any{
							"from": mailFrom, "to": recipients,
							"bytes": body.Len(), "body": truncateStr(body.String(), 2000),
						},
					})
					body.Reset()
					recipients = nil
					_, _ = conn.Write([]byte("250 2.0.0 Ok: queued as " + strings.ToUpper(eventlog.RandID(6)) + "\r\n"))
					continue
				}
				if body.Len() < 64*1024 {
					body.WriteString(line)
					body.WriteString("\n")
				}
				continue
			}

			cmd, arg := splitFtpLine(line)
			verb := strings.ToUpper(cmd)
			log("command", eventlog.Event{
				Command: line, Username: username,
				Details: map[string]any{"cmd": verb, "arg": arg},
			})

			switch verb {
			case "EHLO", "HELO":
				if verb == "HELO" {
					_, _ = conn.Write([]byte("250 " + host + "\r\n"))
					continue
				}
				_, _ = conn.Write([]byte("250-" + host + "\r\n" +
					"250-PIPELINING\r\n250-SIZE 10240000\r\n250-VRFY\r\n250-ETRN\r\n" +
					"250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250 CHUNKING\r\n"))
			case "AUTH":
				user, pass, ok := smtpAuth(conn, r, arg)
				if !ok {
					_, _ = conn.Write([]byte("535 5.7.8 Error: authentication failed\r\n"))
					continue
				}
				username = user
				store.SetSessionUsername(sessionID, username)
				accepted := shouldAccept(cfg.FakeAuth, user, pass)
				authed = accepted
				log(ternary(accepted, "auth_success", "login_attempt"), eventlog.Event{
					Username: user, Password: pass,
					Details: map[string]any{"accepted": accepted, "mechanism": strings.ToUpper(firstWord(arg))},
				})
				if accepted {
					_, _ = conn.Write([]byte("235 2.7.0 Authentication successful\r\n"))
				} else {
					_, _ = conn.Write([]byte("535 5.7.8 Error: authentication failed\r\n"))
				}
			case "MAIL":
				mailFrom = trimAddress(arg)
				_, _ = conn.Write([]byte("250 2.1.0 Ok\r\n"))
			case "RCPT":
				rcpt := trimAddress(arg)
				recipients = append(recipients, rcpt)
				// An open relay is exactly what spam scanners are hunting for,
				// so accepting keeps them talking (nothing is ever delivered).
				log("relay_attempt", eventlog.Event{
					Username: username, Command: "RCPT TO:" + rcpt,
					Details: map[string]any{"from": mailFrom, "to": rcpt, "authenticated": authed},
				})
				_, _ = conn.Write([]byte("250 2.1.5 Ok\r\n"))
			case "DATA":
				if len(recipients) == 0 {
					_, _ = conn.Write([]byte("503 5.5.1 Error: need RCPT command\r\n"))
					continue
				}
				inData = true
				_, _ = conn.Write([]byte("354 End data with <CR><LF>.<CR><LF>\r\n"))
			case "VRFY", "EXPN":
				_, _ = conn.Write([]byte("252 2.0.0 Cannot VRFY user, but will accept message\r\n"))
			case "STARTTLS":
				_, _ = conn.Write([]byte("454 4.7.0 TLS not available due to temporary reason\r\n"))
			case "RSET":
				mailFrom, recipients = "", nil
				_, _ = conn.Write([]byte("250 2.0.0 Ok\r\n"))
			case "NOOP":
				_, _ = conn.Write([]byte("250 2.0.0 Ok\r\n"))
			case "QUIT":
				_, _ = conn.Write([]byte("221 2.0.0 Bye\r\n"))
				return
			default:
				_, _ = conn.Write([]byte("502 5.5.2 Error: command not recognized\r\n"))
			}
			_ = ctx
		}
	})
	return t
}

// smtpAuth walks the AUTH exchange for the PLAIN and LOGIN mechanisms.
func smtpAuth(conn net.Conn, r *bufio.Reader, arg string) (string, string, bool) {
	fields := strings.Fields(arg)
	if len(fields) == 0 {
		return "", "", false
	}
	switch strings.ToUpper(fields[0]) {
	case "PLAIN":
		payload := ""
		if len(fields) > 1 {
			payload = fields[1]
		} else {
			_, _ = conn.Write([]byte("334 \r\n"))
			line, err := r.ReadString('\n')
			if err != nil {
				return "", "", false
			}
			payload = strings.TrimSpace(line)
		}
		raw, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return "", "", false
		}
		// authorize-id \0 authenticate-id \0 password
		parts := strings.Split(string(raw), "\x00")
		if len(parts) >= 3 {
			return parts[1], parts[2], true
		}
		if len(parts) == 2 {
			return parts[0], parts[1], true
		}
		return string(raw), "", true
	case "LOGIN":
		_, _ = conn.Write([]byte("334 VXNlcm5hbWU6\r\n")) // "Username:"
		userLine, err := r.ReadString('\n')
		if err != nil {
			return "", "", false
		}
		_, _ = conn.Write([]byte("334 UGFzc3dvcmQ6\r\n")) // "Password:"
		passLine, err := r.ReadString('\n')
		if err != nil {
			return "", "", false
		}
		return decodeB64(strings.TrimSpace(userLine)), decodeB64(strings.TrimSpace(passLine)), true
	}
	return "", "", false
}

func NewIMAP(cfg config.Service, store *eventlog.Store) *TCP {
	var t *TCP
	t = NewTCP("imap", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		cfg := t.Cfg()
		banner := cfg.Banner
		if banner == "" {
			banner = "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN AUTH=LOGIN] Dovecot (Ubuntu) ready.\r\n"
		}
		_, _ = conn.Write([]byte(banner))

		r := bufio.NewReader(conn)
		log := func(typ string, e eventlog.Event) {
			e.Service, e.Type, e.SessionID = "imap", typ, sessionID
			e.RemoteIP, e.RemotePort, e.LocalPort = meta.RemoteIP, meta.RemotePort, meta.LocalPort
			store.Log(e)
		}
		selected := false
		var username string

		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			tag, rest := splitFtpLine(line)
			cmd, arg := splitFtpLine(rest)
			verb := strings.ToUpper(cmd)
			if tag == "" {
				continue
			}
			log("command", eventlog.Event{
				Command: line, Username: username,
				Details: map[string]any{"tag": tag, "cmd": verb, "arg": arg},
			})

			finish := func(accepted bool, user, pass string) {
				username = user
				store.SetSessionUsername(sessionID, user)
				log(ternary(accepted, "auth_success", "login_attempt"), eventlog.Event{
					Username: user, Password: pass,
					Details: map[string]any{"accepted": accepted},
				})
				if accepted {
					_, _ = conn.Write([]byte(tag + " OK [CAPABILITY IMAP4rev1 IDLE] Logged in\r\n"))
				} else {
					_, _ = conn.Write([]byte(tag + " NO [AUTHENTICATIONFAILED] Authentication failed.\r\n"))
				}
			}

			switch verb {
			case "CAPABILITY":
				_, _ = conn.Write([]byte("* CAPABILITY IMAP4rev1 SASL-IR IDLE AUTH=PLAIN AUTH=LOGIN\r\n" +
					tag + " OK Capability completed.\r\n"))
			case "LOGIN":
				user, pass := splitImapLogin(arg)
				finish(shouldAccept(cfg.FakeAuth, user, pass), user, pass)
			case "AUTHENTICATE":
				mech := strings.ToUpper(firstWord(arg))
				if mech != "PLAIN" && mech != "LOGIN" {
					_, _ = conn.Write([]byte(tag + " NO Unsupported authentication mechanism.\r\n"))
					continue
				}
				_, _ = conn.Write([]byte("+ \r\n"))
				payload, err := r.ReadString('\n')
				if err != nil {
					return
				}
				raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
				parts := strings.Split(string(raw), "\x00")
				user, pass := "", ""
				switch {
				case len(parts) >= 3:
					user, pass = parts[1], parts[2]
				case len(parts) == 2:
					user, pass = parts[0], parts[1]
				default:
					user = string(raw)
				}
				finish(shouldAccept(cfg.FakeAuth, user, pass), user, pass)
			case "ID":
				_, _ = conn.Write([]byte("* ID (\"name\" \"Dovecot\")\r\n" + tag + " OK ID completed.\r\n"))
			case "LIST":
				_, _ = conn.Write([]byte("* LIST (\\HasNoChildren) \".\" INBOX\r\n" + tag + " OK List completed.\r\n"))
			case "SELECT", "EXAMINE":
				selected = true
				_, _ = conn.Write([]byte("* 0 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 1] UIDs valid\r\n" +
					tag + " OK [READ-WRITE] Select completed.\r\n"))
			case "FETCH", "UID", "SEARCH":
				if !selected {
					_, _ = conn.Write([]byte(tag + " BAD No mailbox selected.\r\n"))
					continue
				}
				_, _ = conn.Write([]byte(tag + " OK Completed.\r\n"))
			case "LOGOUT":
				_, _ = conn.Write([]byte("* BYE Logging out\r\n" + tag + " OK Logout completed.\r\n"))
				return
			case "STARTTLS":
				_, _ = conn.Write([]byte(tag + " NO TLS unavailable.\r\n"))
			default:
				_, _ = conn.Write([]byte(tag + " BAD Error in IMAP command.\r\n"))
			}
			_ = ctx
		}
	})
	return t
}

func NewPOP3(cfg config.Service, store *eventlog.Store) *TCP {
	var t *TCP
	t = NewTCP("pop3", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		cfg := t.Cfg()
		banner := cfg.Banner
		if banner == "" {
			banner = "+OK Dovecot (Ubuntu) ready.\r\n"
		}
		_, _ = conn.Write([]byte(banner))

		r := bufio.NewReader(conn)
		log := func(typ string, e eventlog.Event) {
			e.Service, e.Type, e.SessionID = "pop3", typ, sessionID
			e.RemoteIP, e.RemotePort, e.LocalPort = meta.RemoteIP, meta.RemotePort, meta.LocalPort
			store.Log(e)
		}
		var username string
		authed := false

		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			cmd, arg := splitFtpLine(line)
			verb := strings.ToUpper(cmd)
			log("command", eventlog.Event{
				Command: line, Username: username,
				Details: map[string]any{"cmd": verb, "arg": arg},
			})

			switch verb {
			case "CAPA":
				_, _ = conn.Write([]byte("+OK\r\nTOP\r\nUSER\r\nSASL PLAIN LOGIN\r\nUIDL\r\n.\r\n"))
			case "USER":
				username = arg
				store.SetSessionUsername(sessionID, username)
				_, _ = conn.Write([]byte("+OK\r\n"))
			case "PASS":
				accepted := shouldAccept(cfg.FakeAuth, username, arg)
				authed = accepted
				log(ternary(accepted, "auth_success", "login_attempt"), eventlog.Event{
					Username: username, Password: arg,
					Details: map[string]any{"accepted": accepted},
				})
				if accepted {
					_, _ = conn.Write([]byte("+OK Logged in.\r\n"))
				} else {
					_, _ = conn.Write([]byte("-ERR [AUTH] Authentication failed.\r\n"))
				}
			case "APOP":
				user, digest := splitFtpLine(arg)
				username = user
				log("login_attempt", eventlog.Event{
					Username: user, Password: digest,
					Details: map[string]any{"mechanism": "APOP"},
				})
				_, _ = conn.Write([]byte("-ERR [AUTH] Authentication failed.\r\n"))
			case "STAT":
				if !authed {
					_, _ = conn.Write([]byte("-ERR Not authenticated.\r\n"))
					continue
				}
				_, _ = conn.Write([]byte("+OK 0 0\r\n"))
			case "LIST", "UIDL":
				if !authed {
					_, _ = conn.Write([]byte("-ERR Not authenticated.\r\n"))
					continue
				}
				_, _ = conn.Write([]byte("+OK 0 messages:\r\n.\r\n"))
			case "QUIT":
				_, _ = conn.Write([]byte("+OK Logging out.\r\n"))
				return
			default:
				_, _ = conn.Write([]byte("-ERR Unknown command.\r\n"))
			}
			_ = ctx
		}
	})
	return t
}

func decodeB64(s string) string {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return string(raw)
}

func firstWord(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// trimAddress turns `FROM:<bob@example.com> SIZE=42` into `bob@example.com`.
func trimAddress(arg string) string {
	s := arg
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimSpace(s)
	if i := strings.Index(s, " "); i > 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	return s
}

// splitImapLogin handles `LOGIN user pass` with optional quoting.
func splitImapLogin(arg string) (string, string) {
	fields := splitQuoted(arg)
	switch len(fields) {
	case 0:
		return "", ""
	case 1:
		return fields[0], ""
	default:
		return fields[0], fields[1]
	}
}

func splitQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == ' ' && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
