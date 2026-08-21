package honeypots

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

// Open-proxy honeypots. Proxy scanners are relentless: they look for a box
// that will forward traffic for them, then use it to hide credential
// stuffing, spam, and ad fraud. Nothing is ever forwarded here — the value
// is in seeing *where* they wanted to go, and any proxy credentials they
// try on the way.

// NewHTTPProxy emulates a Squid-style forward proxy (3128 / 8080).
func NewHTTPProxy(cfg config.Service, store *eventlog.Store) *TCP {
	var t *TCP
	t = NewTCP("http-proxy", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		runHTTPProxy(t, "http-proxy", conn, sessionID, meta, store)
		_ = ctx
	})
	return t
}

// NewSquid is the same emulator under the name/banner of a Squid cache, for
// operators who want the service to show up as "squid" in the dashboard.
func NewSquid(cfg config.Service, store *eventlog.Store) *TCP {
	var t *TCP
	t = NewTCP("squid", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		runHTTPProxy(t, "squid", conn, sessionID, meta, store)
		_ = ctx
	})
	return t
}

func runHTTPProxy(t *TCP, name string, conn net.Conn, sessionID string, meta ConnMeta, store *eventlog.Store) {
	cfg := t.Cfg()
	server := cfg.ServerHeader
	if server == "" {
		server = "squid/6.6"
	}
	r := bufio.NewReader(conn)
	log := func(typ string, e eventlog.Event) {
		e.Service, e.Type, e.SessionID = name, typ, sessionID
		e.RemoteIP, e.RemotePort, e.LocalPort = meta.RemoteIP, meta.RemotePort, meta.LocalPort
		store.Log(e)
	}

	for {
		requestLine, err := r.ReadString('\n')
		if err != nil {
			return
		}
		requestLine = strings.TrimRight(requestLine, "\r\n")
		if requestLine == "" {
			continue
		}
		fields := strings.Fields(requestLine)
		if len(fields) < 2 {
			_, _ = conn.Write([]byte(proxyError(server, 400, "Bad Request")))
			return
		}
		method, target := strings.ToUpper(fields[0]), fields[1]

		headers, err := readHTTPHeaders(r)
		if err != nil {
			return
		}
		user, pass := proxyCredentials(headers)
		if user != "" {
			store.SetSessionUsername(sessionID, user)
		}

		details := map[string]any{
			"method": method, "target": target,
			"userAgent": headers["user-agent"], "host": headers["host"],
			"viaProxyAuth": user != "",
		}

		switch method {
		case "CONNECT":
			// The classic open-proxy probe: CONNECT to a mail server or to a
			// site the scanner controls, to see whether the tunnel opens.
			host, port := splitProxyTarget(target, 443)
			details["destHost"], details["destPort"] = host, port
			details["intent"] = proxyIntent(port)
			log("proxy_connect", eventlog.Event{
				Command: "CONNECT " + target, Username: user, Password: pass,
				Details: details,
			})
			if user != "" || pass != "" {
				log("login_attempt", eventlog.Event{
					Username: user, Password: pass,
					Details: map[string]any{"realm": "proxy", "accepted": false},
				})
			}
			_, _ = conn.Write([]byte(proxyError(server, 403, "Forbidden")))
			return
		case "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH":
			if strings.HasPrefix(strings.ToLower(target), "http://") ||
				strings.HasPrefix(strings.ToLower(target), "https://") {
				// Absolute-URI request = someone using us as a forward proxy.
				log("proxy_request", eventlog.Event{
					Command: method + " " + target, Username: user, Password: pass,
					Details: details,
				})
				if user != "" || pass != "" {
					log("login_attempt", eventlog.Event{
						Username: user, Password: pass,
						Details: map[string]any{"realm": "proxy", "accepted": false},
					})
				}
				_, _ = conn.Write([]byte(proxyError(server, 403, "Forbidden")))
				return
			}
			// Relative path: a direct hit on the proxy port, often a scanner
			// fingerprinting the cache manager.
			log("request", eventlog.Event{
				Command: method + " " + target, Username: user, Password: pass,
				Details: details,
			})
			_, _ = conn.Write([]byte(proxyError(server, 400, "Invalid URL")))
			return
		default:
			log("payload", eventlog.Event{Command: requestLine, Details: details})
			_, _ = conn.Write([]byte(proxyError(server, 405, "Method Not Allowed")))
			return
		}
	}
}

func readHTTPHeaders(r *bufio.Reader) (map[string]string, error) {
	headers := map[string]string{}
	for i := 0; i < 64; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			return headers, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return headers, nil
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		headers[key] = strings.TrimSpace(line[idx+1:])
	}
	return headers, nil
}

func proxyCredentials(headers map[string]string) (string, string) {
	for _, key := range []string{"proxy-authorization", "authorization"} {
		value := headers[key]
		if value == "" {
			continue
		}
		parts := strings.SplitN(value, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "basic") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
		if err != nil {
			continue
		}
		user, pass, _ := strings.Cut(string(raw), ":")
		return user, pass
	}
	return "", ""
}

func splitProxyTarget(target string, defaultPort int) (string, int) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return target, defaultPort
	}
	port, convErr := strconv.Atoi(portStr)
	if convErr != nil {
		return host, defaultPort
	}
	return host, port
}

// proxyIntent labels the well-known abuse pattern behind a CONNECT port.
func proxyIntent(port int) string {
	switch port {
	case 25, 465, 587:
		return "spam relay"
	case 443, 8443:
		return "tunnelled https"
	case 22:
		return "ssh tunnel"
	case 6667, 6697:
		return "irc"
	case 5222:
		return "xmpp"
	default:
		return "unknown"
	}
}

func proxyError(server string, code int, reason string) string {
	body := fmt.Sprintf(`<!DOCTYPE html><html><head><title>ERROR: %s</title></head>
<body><h1>ERROR</h1><p>The requested URL could not be retrieved</p><hr><address>Generated by %s</address></body></html>`, reason, server)
	extra := ""
	if code == 403 {
		extra = "Proxy-Authenticate: Basic realm=\"proxy\"\r\n"
	}
	return fmt.Sprintf("HTTP/1.1 %d %s\r\nServer: %s\r\nMime-Version: 1.0\r\n"+
		"Content-Type: text/html;charset=utf-8\r\nContent-Length: %d\r\n%s"+
		"X-Cache: MISS from proxy\r\nVia: 1.1 proxy (%s)\r\nConnection: close\r\n\r\n%s",
		code, reason, server, len(body), extra, server, body)
}

// NewSOCKS emulates SOCKS4/4a/5 (port 1080). SOCKS5 username/password auth
// (RFC 1929) hands us cleartext credentials, and every request carries the
// destination the scanner wanted to reach.
func NewSOCKS(cfg config.Service, store *eventlog.Store) *TCP {
	var t *TCP
	t = NewTCP("socks", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		cfg := t.Cfg()
		r := bufio.NewReader(conn)
		log := func(typ string, e eventlog.Event) {
			e.Service, e.Type, e.SessionID = "socks", typ, sessionID
			e.RemoteIP, e.RemotePort, e.LocalPort = meta.RemoteIP, meta.RemotePort, meta.LocalPort
			store.Log(e)
		}

		version, err := r.ReadByte()
		if err != nil {
			return
		}
		switch version {
		case 0x04:
			handleSOCKS4(r, conn, log)
		case 0x05:
			handleSOCKS5(r, conn, log, cfg, store, sessionID)
		default:
			log("payload", eventlog.Event{
				Details: map[string]any{"version": version, "note": "not a SOCKS greeting"},
			})
		}
		_ = ctx
	})
	return t
}

func handleSOCKS4(r *bufio.Reader, conn net.Conn, log func(string, eventlog.Event)) {
	// VN(read) CD DSTPORT(2) DSTIP(4) USERID null-terminated [DOMAIN for 4a]
	head := make([]byte, 7)
	if _, err := io.ReadFull(r, head); err != nil {
		return
	}
	command := head[0]
	port := int(head[1])<<8 | int(head[2])
	ip := net.IPv4(head[3], head[4], head[5], head[6]).String()
	userID, _ := r.ReadString(0x00)
	userID = strings.TrimRight(userID, "\x00")
	host := ip
	// SOCKS4a signals "resolve this name for me" with 0.0.0.x.
	if head[3] == 0 && head[4] == 0 && head[5] == 0 && head[6] != 0 {
		domain, _ := r.ReadString(0x00)
		host = strings.TrimRight(domain, "\x00")
	}
	log("proxy_connect", eventlog.Event{
		Username: userID,
		Command:  fmt.Sprintf("SOCKS4 %s %s:%d", socksCommand(command), host, port),
		Details: map[string]any{
			"version": 4, "command": socksCommand(command),
			"destHost": host, "destPort": port, "userId": userID,
			"intent": proxyIntent(port),
		},
	})
	// 0x5b = request rejected or failed.
	_, _ = conn.Write([]byte{0x00, 0x5b, head[1], head[2], head[3], head[4], head[5], head[6]})
}

func handleSOCKS5(r *bufio.Reader, conn net.Conn, log func(string, eventlog.Event),
	cfg config.Service, store *eventlog.Store, sessionID string) {
	nMethods, err := r.ReadByte()
	if err != nil {
		return
	}
	methods := make([]byte, int(nMethods))
	if _, err := io.ReadFull(r, methods); err != nil {
		return
	}
	offersUserPass := false
	for _, m := range methods {
		if m == 0x02 {
			offersUserPass = true
		}
	}
	log("client_hello", eventlog.Event{
		Details: map[string]any{"version": 5, "methods": methods, "userPassOffered": offersUserPass},
	})

	if offersUserPass {
		// Ask for credentials — that is the whole reason to answer at all.
		_, _ = conn.Write([]byte{0x05, 0x02})
		if _, err := r.ReadByte(); err != nil { // auth version
			return
		}
		userLen, err := r.ReadByte()
		if err != nil {
			return
		}
		user := make([]byte, int(userLen))
		if _, err := io.ReadFull(r, user); err != nil {
			return
		}
		passLen, err := r.ReadByte()
		if err != nil {
			return
		}
		pass := make([]byte, int(passLen))
		if _, err := io.ReadFull(r, pass); err != nil {
			return
		}
		store.SetSessionUsername(sessionID, string(user))
		accepted := shouldAccept(cfg.FakeAuth, string(user), string(pass))
		log(ternary(accepted, "auth_success", "login_attempt"), eventlog.Event{
			Username: string(user), Password: string(pass),
			Details: map[string]any{"version": 5, "accepted": accepted},
		})
		if !accepted {
			_, _ = conn.Write([]byte{0x01, 0x01})
			return
		}
		_, _ = conn.Write([]byte{0x01, 0x00})
	} else {
		_, _ = conn.Write([]byte{0x05, 0x00}) // no auth required
	}

	// CONNECT request: VER CMD RSV ATYP DST.ADDR DST.PORT
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return
	}
	command := head[1]
	var host string
	switch head[3] {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(r, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case 0x03:
		l, err := r.ReadByte()
		if err != nil {
			return
		}
		name := make([]byte, int(l))
		if _, err := io.ReadFull(r, name); err != nil {
			return
		}
		host = string(name)
	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(r, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	default:
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, portBytes); err != nil {
		return
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])

	log("proxy_connect", eventlog.Event{
		Command: fmt.Sprintf("SOCKS5 %s %s:%d", socksCommand(command), host, port),
		Details: map[string]any{
			"version": 5, "command": socksCommand(command),
			"destHost": host, "destPort": port, "intent": proxyIntent(port),
		},
	})
	// 0x02 = connection not allowed by ruleset.
	_, _ = conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func socksCommand(c byte) string {
	switch c {
	case 0x01:
		return "CONNECT"
	case 0x02:
		return "BIND"
	case 0x03:
		return "UDP-ASSOCIATE"
	default:
		return "UNKNOWN"
	}
}
