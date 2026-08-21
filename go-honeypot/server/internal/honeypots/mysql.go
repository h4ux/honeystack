package honeypots

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	mrand "math/rand"
	"net"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

func NewMySQL(cfg config.Service, store *eventlog.Store) *TCP {
	var t *TCP
	t = NewTCP("mysql", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		cfg := t.Cfg()
		version := cfg.ServerVersion
		if version == "" {
			version = "8.0.36"
		}
		salt1 := make([]byte, 8)
		_, _ = cryptorand.Read(salt1)
		salt2 := make([]byte, 12)
		_, _ = cryptorand.Read(salt2)
		threadID := mrand.Uint32()

		var b bytes.Buffer
		b.WriteByte(0x0a)
		b.WriteString(version)
		b.WriteByte(0)
		_ = binary.Write(&b, binary.LittleEndian, threadID)
		b.Write(salt1)
		b.WriteByte(0)
		_ = binary.Write(&b, binary.LittleEndian, uint16(0xffff))
		b.WriteByte(0x21)
		_ = binary.Write(&b, binary.LittleEndian, uint16(0x0002))
		_ = binary.Write(&b, binary.LittleEndian, uint16(0x807f))
		b.WriteByte(0x15)
		b.Write(make([]byte, 10))
		b.Write(salt2)
		b.WriteByte(0)

		hdr := packetHeader(b.Len(), 0)
		_, _ = conn.Write(append(hdr, b.Bytes()...))

		received := make([]byte, 0, 1024)
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			received = append(received, buf[:n]...)
			if len(received) > 8192 {
				return
			}
			if user, authHex, database, ok := parseHandshakeResponse(received); ok {
				pw := ""
				if authHex != "" {
					pw = "<sha1:" + authHex + ">"
				}
				accepted := shouldAccept(cfg.FakeAuth, user, pw)
				store.SetSessionUsername(sessionID, user)
				store.Log(eventlog.Event{
					Service: "mysql", Type: ternary(accepted, "auth_success", "login_attempt"), SessionID: sessionID,
					RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
					Username: user, Password: pw,
					Details: map[string]any{"database": database, "accepted": accepted},
				})
				if !accepted {
					errPkt := errorPacket(1045, "28000", "Access denied for user '"+user+"'@'"+meta.RemoteIP+"' (using password: YES)")
					_, _ = conn.Write(errPkt)
					return
				}
				_, _ = conn.Write(okPacket(2))
				received = received[:0]
				continue
			}
			_ = ctx
		}
	})
	return t
}

func packetHeader(bodyLen, seq int) []byte {
	h := make([]byte, 4)
	h[0] = byte(bodyLen)
	h[1] = byte(bodyLen >> 8)
	h[2] = byte(bodyLen >> 16)
	h[3] = byte(seq)
	return h
}

func parseHandshakeResponse(buf []byte) (string, string, string, bool) {
	if len(buf) < 5 {
		return "", "", "", false
	}
	payloadLen := int(buf[0]) | int(buf[1])<<8 | int(buf[2])<<16
	if len(buf) < 4+payloadLen {
		return "", "", "", false
	}
	p := buf[4 : 4+payloadLen]
	if len(p) < 32 {
		return "", "", "", false
	}
	off := 32
	end := bytes.IndexByte(p[off:], 0)
	if end < 0 {
		return "", "", "", false
	}
	username := string(p[off : off+end])
	off += end + 1
	if off >= len(p) {
		return username, "", "", true
	}
	authLen := int(p[off])
	off++
	if off+authLen > len(p) {
		return username, "", "", true
	}
	auth := p[off : off+authLen]
	off += authLen
	var database string
	if off < len(p) {
		if idx := bytes.IndexByte(p[off:], 0); idx >= 0 {
			database = string(p[off : off+idx])
		}
	}
	authHex := hex.EncodeToString(auth)
	if len(authHex) > 40 {
		authHex = authHex[:40]
	}
	return username, authHex, database, true
}

func errorPacket(code int, sqlState, message string) []byte {
	var body bytes.Buffer
	body.WriteByte(0xff)
	_ = binary.Write(&body, binary.LittleEndian, uint16(code))
	body.WriteByte('#')
	body.WriteString(sqlState)
	body.WriteString(message)
	return append(packetHeader(body.Len(), 2), body.Bytes()...)
}

func okPacket(seq int) []byte {
	body := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	return append(packetHeader(len(body), seq), body...)
}
