package honeypots

import (
	"context"
	"encoding/hex"
	"net"
	"strings"
	"unicode"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

// NewClickHouseNative emulates the ClickHouse native TCP endpoint. Native
// protocol revisions vary, so the honeypot deliberately stays conservative:
// it captures the ClientHello/query bytes and returns a plausible server
// handshake prefix without attempting to execute or fully decode queries.
func NewClickHouseNative(cfg config.Service, store *eventlog.Store) *TCP {
	return NewTCP("clickhouse-native", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		buf := make([]byte, 64*1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		data := buf[:n]
		printable := printableRuns(data)
		client := ""
		if len(data) > 1 {
			if s, _, ok := readCHString(data, 1); ok {
				client = s
			}
		}
		store.Log(eventlog.Event{
			Service: "clickhouse-native", Type: "client_hello", SessionID: sessionID,
			RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
			Command: strings.Join(printable, " "),
			Details: map[string]any{
				"client": client, "length": n,
				"hex":     hex.EncodeToString(data[:minInt(n, 256)]),
				"strings": printable,
			},
		})

		// ServerHello packet type (0), server name and version components.
		// This is enough for native-protocol scanners to distinguish the
		// endpoint from a generic open TCP port.
		version := firstNonEmpty(cfg.ServerVersion, "24.8.4.13")
		reply := []byte{0x00}
		reply = appendCHString(reply, "ClickHouse")
		reply = append(reply, 0x18, 0x08) // major 24, minor 8
		reply = appendCHString(reply, version)
		_, _ = conn.Write(reply)
		_ = ctx
	})
}

func readCHString(b []byte, off int) (string, int, bool) {
	n, used, ok := readUVarint(b[off:])
	if !ok || n > 4096 || off+used+int(n) > len(b) {
		return "", off, false
	}
	start := off + used
	return string(b[start : start+int(n)]), start + int(n), true
}

func appendCHString(dst []byte, s string) []byte {
	dst = appendUVarint(dst, uint64(len(s)))
	return append(dst, s...)
}

func readUVarint(b []byte) (uint64, int, bool) {
	var x uint64
	for i := 0; i < len(b) && i < 10; i++ {
		c := b[i]
		if c < 0x80 {
			if i == 9 && c > 1 {
				return 0, 0, false
			}
			return x | uint64(c)<<uint(7*i), i + 1, true
		}
		x |= uint64(c&0x7f) << uint(7*i)
	}
	return 0, 0, false
}

func appendUVarint(dst []byte, x uint64) []byte {
	for x >= 0x80 {
		dst = append(dst, byte(x)|0x80)
		x >>= 7
	}
	return append(dst, byte(x))
}

func printableRuns(b []byte) []string {
	var out []string
	var run []rune
	flush := func() {
		if len(run) >= 3 {
			out = append(out, string(run))
		}
		run = run[:0]
	}
	for _, c := range b {
		r := rune(c)
		if unicode.IsPrint(r) && c < 0x7f {
			run = append(run, r)
		} else {
			flush()
		}
	}
	flush()
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
