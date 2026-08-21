package honeypots

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"unicode/utf16"

	"github.com/example/honeypot/internal/config"
	"github.com/example/honeypot/internal/eventlog"
)

// TDS packet types used during SQL Server connection setup.
const (
	tdsSQLBatch = 0x01
	tdsLogin7   = 0x10
	tdsPrelogin = 0x12
)

func NewMSSQL(cfg config.Service, store *eventlog.Store) *TCP {
	return NewTCP("mssql", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		for packets := 0; packets < 5; packets++ {
			header := make([]byte, 8)
			if _, err := readFull(conn, header); err != nil {
				return
			}
			length := int(binary.BigEndian.Uint16(header[2:4]))
			if length < 8 || length > 64*1024 {
				return
			}
			payload := make([]byte, length-8)
			if _, err := readFull(conn, payload); err != nil {
				return
			}

			switch header[0] {
			case tdsPrelogin:
				store.Log(eventlog.Event{
					Service: "mssql", Type: "prelogin", SessionID: sessionID,
					RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
					Details: map[string]any{"length": len(payload), "hex": hex.EncodeToString(payload[:minInt(len(payload), 256)])},
				})
				_, _ = conn.Write(tdsPacket(0x04, mssqlPreloginResponse()))

			case tdsLogin7:
				login := parseTDSLogin7(payload)
				store.Log(eventlog.Event{
					Service: "mssql", Type: "login_attempt", SessionID: sessionID,
					RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
					Username: login.User, Password: login.Password,
					Details: map[string]any{
						"host": login.Host, "application": login.Application,
						"server": login.Server, "database": login.Database,
					},
				})
				// TDS ERROR token: login failed for user. Most clients display
				// this as SQL Server error 18456.
				_, _ = conn.Write(tdsPacket(0x04, mssqlLoginFailed(login.User)))
				return

			case tdsSQLBatch:
				query := decodeUTF16LE(payload)
				store.Log(eventlog.Event{
					Service: "mssql", Type: "query", SessionID: sessionID,
					RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
					Command: strings.TrimSpace(query),
				})
				return

			default:
				store.Log(eventlog.Event{
					Service: "mssql", Type: "payload", SessionID: sessionID,
					RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
					Details: map[string]any{"packetType": header[0], "length": len(payload), "hex": hex.EncodeToString(payload[:minInt(len(payload), 256)])},
				})
			}
		}
		_ = cfg
		_ = ctx
	})
}

type tdsLogin struct {
	Host, User, Password, Application, Server, Database string
}

func parseTDSLogin7(p []byte) tdsLogin {
	// LOGIN7 variable-field offset table starts at byte 36. Offsets are
	// measured from the start of the LOGIN7 payload; lengths are UTF-16
	// character counts.
	return tdsLogin{
		Host:        tdsField(p, 36, false),
		User:        tdsField(p, 40, false),
		Password:    tdsField(p, 44, true),
		Application: tdsField(p, 48, false),
		Server:      tdsField(p, 52, false),
		Database:    tdsField(p, 68, false),
	}
}

func tdsField(p []byte, tableOffset int, password bool) string {
	if tableOffset+4 > len(p) {
		return ""
	}
	off := int(binary.LittleEndian.Uint16(p[tableOffset : tableOffset+2]))
	chars := int(binary.LittleEndian.Uint16(p[tableOffset+2 : tableOffset+4]))
	n := chars * 2
	if off < 0 || n < 0 || off+n > len(p) {
		return ""
	}
	raw := append([]byte(nil), p[off:off+n]...)
	if password {
		for i, c := range raw {
			// LOGIN7 password obfuscation: swap nibbles, then XOR 0xA5.
			x := c ^ 0xA5
			raw[i] = (x << 4) | (x >> 4)
		}
	}
	return strings.TrimRight(decodeUTF16LE(raw), "\x00")
}

func decodeUTF16LE(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	return string(utf16.Decode(u))
}

func encodeUTF16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

func tdsPacket(packetType byte, payload []byte) []byte {
	out := make([]byte, 8+len(payload))
	out[0] = packetType
	out[1] = 0x01 // end of message
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	out[6] = 0x01
	copy(out[8:], payload)
	return out
}

func mssqlPreloginResponse() []byte {
	// VERSION(offset 11,len 6), ENCRYPTION(offset 17,len 1), terminator.
	return []byte{
		0x00, 0x00, 0x0b, 0x00, 0x06,
		0x01, 0x00, 0x11, 0x00, 0x01,
		0xff,
		0x10, 0x00, 0x10, 0x27, 0x00, 0x00, // SQL Server 2022-ish
		0x02, // encryption not supported
	}
}

func mssqlLoginFailed(user string) []byte {
	msg := "Login failed for user '" + user + "'."
	msg16 := encodeUTF16LE(msg)
	server16 := encodeUTF16LE("MSSQLSERVER")
	// ERROR token payload.
	tokenLen := 4 + 1 + 1 + 2 + len(msg16) + 1 + len(server16) + 1 + 0 + 4
	b := make([]byte, 0, tokenLen+16)
	b = append(b, 0xaa)
	var x [4]byte
	binary.LittleEndian.PutUint16(x[:2], uint16(tokenLen))
	b = append(b, x[:2]...)
	binary.LittleEndian.PutUint32(x[:], 18456)
	b = append(b, x[:]...)
	b = append(b, 0x01, 0x0e) // state, severity
	binary.LittleEndian.PutUint16(x[:2], uint16(len([]rune(msg))))
	b = append(b, x[:2]...)
	b = append(b, msg16...)
	b = append(b, byte(len([]rune("MSSQLSERVER"))))
	b = append(b, server16...)
	b = append(b, 0x00) // procedure length
	binary.LittleEndian.PutUint32(x[:], 1)
	b = append(b, x[:]...)
	// DONE token.
	b = append(b, 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	return b
}

func readFull(conn net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := conn.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
