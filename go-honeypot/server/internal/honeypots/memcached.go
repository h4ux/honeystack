package honeypots

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

// NewMemcached emulates the memcached text protocol. Exposed memcached is
// scanned both for cached data and as a UDP/TCP amplification source, so
// the interesting part is which keys and commands are asked for.
func NewMemcached(cfg config.Service, store *eventlog.Store) *TCP {
	var t *TCP
	t = NewTCP("memcached", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		cfg := t.Cfg()
		version := cfg.ServerVersion
		if version == "" {
			version = "1.6.24"
		}
		r := bufio.NewReader(conn)
		log := func(typ string, e eventlog.Event) {
			e.Service, e.Type, e.SessionID = "memcached", typ, sessionID
			e.RemoteIP, e.RemotePort, e.LocalPort = meta.RemoteIP, meta.RemotePort, meta.LocalPort
			store.Log(e)
		}

		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				continue
			}
			fields := strings.Fields(line)
			verb := strings.ToLower(fields[0])
			args := fields[1:]
			log("command", eventlog.Event{
				Command: line,
				Details: map[string]any{"cmd": verb, "args": args},
			})

			switch verb {
			case "version":
				_, _ = conn.Write([]byte("VERSION " + version + "\r\n"))
			case "get", "gets":
				// Nothing is ever stored, so every key misses.
				_, _ = conn.Write([]byte("END\r\n"))
			case "set", "add", "replace", "append", "prepend":
				// <cmd> <key> <flags> <exptime> <bytes> [noreply]
				n := 0
				if len(args) >= 4 {
					n, _ = strconv.Atoi(args[3])
				}
				payload := make([]byte, 0, n)
				if n > 0 && n < 1<<20 {
					buf := make([]byte, n)
					if _, err := readBuffered(r, buf); err != nil {
						return
					}
					payload = buf
				}
				_, _ = r.ReadString('\n') // trailing CRLF
				key := ""
				if len(args) > 0 {
					key = args[0]
				}
				log("payload", eventlog.Event{
					Command: verb + " " + key,
					Details: map[string]any{"key": key, "bytes": n, "value": truncateStr(string(payload), 512)},
				})
				_, _ = conn.Write([]byte("STORED\r\n"))
			case "delete":
				_, _ = conn.Write([]byte("NOT_FOUND\r\n"))
			case "incr", "decr":
				_, _ = conn.Write([]byte("NOT_FOUND\r\n"))
			case "flush_all":
				_, _ = conn.Write([]byte("OK\r\n"))
			case "stats":
				_, _ = conn.Write([]byte(memcachedStats(version, strings.Join(args, " "))))
			case "quit":
				return
			default:
				_, _ = conn.Write([]byte("ERROR\r\n"))
			}
			_ = ctx
		}
	})
	return t
}

func memcachedStats(version, sub string) string {
	switch strings.ToLower(strings.TrimSpace(sub)) {
	case "items", "slabs":
		return "END\r\n"
	case "settings":
		return "STAT maxbytes 67108864\r\nSTAT maxconns 1024\r\nSTAT tcpport 11211\r\nEND\r\n"
	}
	var b strings.Builder
	stats := [][2]string{
		{"pid", "1"}, {"uptime", "864213"}, {"version", version},
		{"pointer_size", "64"}, {"curr_connections", "4"}, {"total_connections", "1827"},
		{"cmd_get", "48213"}, {"cmd_set", "6721"}, {"get_hits", "41288"}, {"get_misses", "6925"},
		{"curr_items", "0"}, {"total_items", "6721"}, {"bytes", "0"}, {"limit_maxbytes", "67108864"},
		{"threads", "4"},
	}
	for _, s := range stats {
		fmt.Fprintf(&b, "STAT %s %s\r\n", s[0], s[1])
	}
	b.WriteString("END\r\n")
	return b.String()
}

// readBuffered fills buf from a bufio.Reader, tolerating short reads.
func readBuffered(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
