package honeypots

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

// VPN-facing honeypots. VPN endpoints are prime targets: a reachable
// concentrator invites credential stuffing and CVE probing, and the mere
// presence of one tells an attacker there is an internal network worth
// getting into. These emulators answer the handshake far enough to record
// who knocked and with what client, and never negotiate a tunnel.

// NewOpenVPN emulates an OpenVPN server. Default is UDP/1194; the same
// emulator serves TCP when the service is configured with protocol "tcp".
func NewOpenVPN(name string, cfg config.Service, store *eventlog.Store) *UDP {
	return NewUDPProto(name, cfg, store, func(payload []byte, meta ConnMeta) UDPReply {
		if len(payload) < 1 {
			return UDPReply{}
		}
		opcode := payload[0] >> 3
		keyID := payload[0] & 0x07
		details := map[string]any{
			"opcode": opcode, "opcodeName": openvpnOpcode(opcode),
			"keyId": keyID, "bytes": len(payload),
		}
		if len(payload) >= 9 {
			details["sessionId"] = hex.EncodeToString(payload[1:9])
		}
		// P_CONTROL_HARD_RESET_CLIENT_V2/V3 is the first packet of a real
		// client handshake; anything else on this port is a scanner.
		if opcode == 7 || opcode == 10 {
			return UDPReply{
				Type:    "client_hello",
				Command: "openvpn " + openvpnOpcode(opcode),
				Details: details,
				// P_CONTROL_HARD_RESET_SERVER_V2 with a random session id so
				// the client keeps talking.
				Response: openvpnServerReset(payload),
			}
		}
		return UDPReply{
			Type:    "payload",
			Command: "openvpn " + openvpnOpcode(opcode),
			Details: details,
		}
	})
}

// NewOpenVPNTCP is the TCP flavour: OpenVPN over TCP prefixes every packet
// with a 16-bit length.
func NewOpenVPNTCP(cfg config.Service, store *eventlog.Store) *TCP {
	var t *TCP
	t = NewTCP("openvpn-tcp", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		log := func(typ string, e eventlog.Event) {
			e.Service, e.Type, e.SessionID = "openvpn-tcp", typ, sessionID
			e.RemoteIP, e.RemotePort, e.LocalPort = meta.RemoteIP, meta.RemotePort, meta.LocalPort
			store.Log(e)
		}
		for {
			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(conn, lenBuf); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(lenBuf))
			if n == 0 || n > 8192 {
				return
			}
			packet := make([]byte, n)
			if _, err := io.ReadFull(conn, packet); err != nil {
				return
			}
			opcode := packet[0] >> 3
			log("client_hello", eventlog.Event{
				Command: "openvpn/tcp " + openvpnOpcode(opcode),
				Details: map[string]any{
					"opcode": opcode, "opcodeName": openvpnOpcode(opcode), "bytes": n,
				},
			})
			if opcode == 7 || opcode == 10 {
				reply := openvpnServerReset(packet)
				out := make([]byte, 2+len(reply))
				binary.BigEndian.PutUint16(out[:2], uint16(len(reply)))
				copy(out[2:], reply)
				_, _ = conn.Write(out)
			}
			_ = ctx
		}
	})
	return t
}

func openvpnServerReset(client []byte) []byte {
	// opcode 8 (P_CONTROL_HARD_RESET_SERVER_V2) << 3, key id 0
	out := []byte{8 << 3}
	out = append(out, randBytes(8)...) // our session id
	out = append(out, 0x00)            // no packet-id ACKs
	if len(client) >= 9 {
		out = append(out, client[1:9]...) // echo the client session id
	}
	out = append(out, 0x00, 0x00, 0x00, 0x00) // packet id 0
	return out
}

func openvpnOpcode(op byte) string {
	switch op {
	case 1:
		return "P_CONTROL_HARD_RESET_CLIENT_V1"
	case 2:
		return "P_CONTROL_HARD_RESET_SERVER_V1"
	case 3:
		return "P_CONTROL_SOFT_RESET_V1"
	case 4:
		return "P_CONTROL_V1"
	case 5:
		return "P_ACK_V1"
	case 6:
		return "P_DATA_V1"
	case 7:
		return "P_CONTROL_HARD_RESET_CLIENT_V2"
	case 8:
		return "P_CONTROL_HARD_RESET_SERVER_V2"
	case 9:
		return "P_DATA_V2"
	case 10:
		return "P_CONTROL_HARD_RESET_CLIENT_V3"
	default:
		return fmt.Sprintf("opcode_%d", op)
	}
}

// NewIKE emulates an IPsec IKE responder on UDP/500 (and 4500 for NAT-T).
func NewIKE(name string, cfg config.Service, store *eventlog.Store) *UDP {
	return NewUDPProto(name, cfg, store, func(payload []byte, meta ConnMeta) UDPReply {
		// NAT-T keepalives and the 4-byte non-ESP marker come through here too.
		if len(payload) == 1 && payload[0] == 0xff {
			return UDPReply{Type: "payload", Command: "ike nat keepalive", Details: map[string]any{"bytes": 1}}
		}
		body := payload
		natT := false
		if len(payload) > 4 && binary.BigEndian.Uint32(payload[:4]) == 0 {
			body = payload[4:]
			natT = true
		}
		if len(body) < 28 {
			return UDPReply{
				Type:    "payload",
				Command: "ike short packet",
				Details: map[string]any{"bytes": len(payload), "hex": hex.EncodeToString(truncateBytes(payload, 32))},
			}
		}
		initiatorSPI := hex.EncodeToString(body[0:8])
		version := body[17]
		exchange := body[18]
		major := version >> 4
		details := map[string]any{
			"initiatorSpi": initiatorSPI,
			"version":      fmt.Sprintf("IKEv%d", major),
			"exchange":     ikeExchange(exchange, major),
			"natTraversal": natT,
			"bytes":        len(payload),
		}
		return UDPReply{
			Type:    "client_hello",
			Command: fmt.Sprintf("IKEv%d %s", major, ikeExchange(exchange, major)),
			Details: details,
			// Answering IKE properly means negotiating crypto; a NO_PROPOSAL
			// notify is enough to look like a live, picky VPN gateway.
			Response: ikeNotify(body, major),
		}
	})
}

func ikeExchange(code byte, major byte) string {
	if major >= 2 {
		switch code {
		case 34:
			return "IKE_SA_INIT"
		case 35:
			return "IKE_AUTH"
		case 36:
			return "CREATE_CHILD_SA"
		case 37:
			return "INFORMATIONAL"
		}
		return fmt.Sprintf("exchange_%d", code)
	}
	switch code {
	case 2:
		return "IDENTITY_PROTECT (main mode)"
	case 4:
		return "AGGRESSIVE"
	case 5:
		return "INFORMATIONAL"
	}
	return fmt.Sprintf("exchange_%d", code)
}

// ikeNotify builds a minimal response: same SPIs, a responder SPI, and a
// NO_PROPOSAL_CHOSEN notify payload.
func ikeNotify(request []byte, major byte) []byte {
	if major < 2 || len(request) < 28 {
		return nil
	}
	notify := []byte{
		0x00,       // next payload: none
		0x00,       // critical/reserved
		0x00, 0x08, // payload length
		0x00,       // protocol id
		0x00,       // SPI size
		0x00, 0x0e, // NO_PROPOSAL_CHOSEN (14)
	}
	header := make([]byte, 28)
	copy(header[0:8], request[0:8])     // initiator SPI
	copy(header[8:16], randBytes(8))    // our responder SPI
	header[16] = 41                     // next payload: notify
	header[17] = request[17]            // version
	header[18] = request[18]            // exchange type
	header[19] = 0x20                   // flags: response
	copy(header[20:24], request[20:24]) // message id
	binary.BigEndian.PutUint32(header[24:28], uint32(len(header)+len(notify)))
	return append(header, notify...)
}

// NewWireGuard emulates a WireGuard endpoint (UDP/51820). WireGuard is
// silent by design, so the useful signal is simply who probes it.
func NewWireGuard(name string, cfg config.Service, store *eventlog.Store) *UDP {
	return NewUDPProto(name, cfg, store, func(payload []byte, meta ConnMeta) UDPReply {
		if len(payload) < 4 {
			return UDPReply{Type: "payload", Details: map[string]any{"bytes": len(payload)}}
		}
		typ := payload[0]
		details := map[string]any{
			"messageType": typ, "messageName": wireguardType(typ), "bytes": len(payload),
		}
		if typ == 1 && len(payload) >= 8 {
			details["senderIndex"] = binary.LittleEndian.Uint32(payload[4:8])
		}
		return UDPReply{
			Type:    ternary(typ == 1, "client_hello", "payload"),
			Command: "wireguard " + wireguardType(typ),
			Details: details,
			// A real peer stays silent for unknown keys — so do we.
		}
	})
}

func wireguardType(t byte) string {
	switch t {
	case 1:
		return "handshake_initiation"
	case 2:
		return "handshake_response"
	case 3:
		return "cookie_reply"
	case 4:
		return "transport_data"
	default:
		return fmt.Sprintf("type_%d", t)
	}
}

// NewL2TP emulates an L2TP control endpoint (UDP/1701).
func NewL2TP(name string, cfg config.Service, store *eventlog.Store) *UDP {
	return NewUDPProto(name, cfg, store, func(payload []byte, meta ConnMeta) UDPReply {
		if len(payload) < 6 {
			return UDPReply{Type: "payload", Details: map[string]any{"bytes": len(payload)}}
		}
		flags := binary.BigEndian.Uint16(payload[0:2])
		isControl := flags&0x8000 != 0
		version := flags & 0x000f
		details := map[string]any{
			"version": version, "control": isControl, "bytes": len(payload),
		}
		// Hostname and vendor arrive as AVPs; pull any printable run out so
		// the operator can see which client called.
		if s := printableRun(payload, 6); s != "" {
			details["strings"] = s
		}
		return UDPReply{
			Type:    "client_hello",
			Command: fmt.Sprintf("l2tp v%d %s", version, ternary(isControl, "control", "data")),
			Details: details,
		}
	})
}

// NewPPTP emulates a PPTP control connection (TCP/1723) — still scanned
// heavily despite being long deprecated.
func NewPPTP(cfg config.Service, store *eventlog.Store) *TCP {
	var t *TCP
	t = NewTCP("pptp", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		log := func(typ string, e eventlog.Event) {
			e.Service, e.Type, e.SessionID = "pptp", typ, sessionID
			e.RemoteIP, e.RemotePort, e.LocalPort = meta.RemoteIP, meta.RemotePort, meta.LocalPort
			store.Log(e)
		}
		for {
			header := make([]byte, 12)
			if _, err := io.ReadFull(conn, header); err != nil {
				return
			}
			length := int(binary.BigEndian.Uint16(header[0:2]))
			msgType := binary.BigEndian.Uint16(header[2:4])
			cookie := binary.BigEndian.Uint32(header[4:8])
			ctrlType := binary.BigEndian.Uint16(header[8:10])
			if length < 12 || length > 4096 {
				return
			}
			body := make([]byte, length-12)
			if len(body) > 0 {
				if _, err := io.ReadFull(conn, body); err != nil {
					return
				}
			}
			details := map[string]any{
				"messageType": msgType, "controlType": ctrlType,
				"controlName": pptpControl(ctrlType),
				"magicCookie": fmt.Sprintf("0x%08x", cookie),
				"bytes":       length,
			}
			if s := printableRun(body, 0); s != "" {
				details["strings"] = s
			}
			log("client_hello", eventlog.Event{
				Command: "pptp " + pptpControl(ctrlType),
				Details: details,
			})
			// Start-Control-Connection-Request (1) -> Reply (2), result "OK".
			if ctrlType == 1 {
				_, _ = conn.Write(pptpStartReply())
			}
			_ = ctx
		}
	})
	return t
}

func pptpStartReply() []byte {
	out := make([]byte, 156)
	binary.BigEndian.PutUint16(out[0:2], 156)        // length
	binary.BigEndian.PutUint16(out[2:4], 1)          // control message
	binary.BigEndian.PutUint32(out[4:8], 0x1a2b3c4d) // magic cookie
	binary.BigEndian.PutUint16(out[8:10], 2)         // Start-Control-Connection-Reply
	binary.BigEndian.PutUint16(out[12:14], 1)        // protocol version 1.0
	out[14] = 1                                      // result code: OK
	out[15] = 0                                      // error code
	binary.BigEndian.PutUint32(out[16:20], 1)        // framing capabilities
	binary.BigEndian.PutUint32(out[20:24], 1)        // bearer capabilities
	binary.BigEndian.PutUint16(out[24:26], 0)        // max channels
	binary.BigEndian.PutUint16(out[26:28], 1)        // firmware revision
	copy(out[28:92], "web-prod-01")                  // host name
	copy(out[92:156], "Linux PPTP Server")           // vendor string
	return out
}

func pptpControl(t uint16) string {
	switch t {
	case 1:
		return "Start-Control-Connection-Request"
	case 2:
		return "Start-Control-Connection-Reply"
	case 3:
		return "Stop-Control-Connection-Request"
	case 5:
		return "Echo-Request"
	case 7:
		return "Outgoing-Call-Request"
	case 10:
		return "Incoming-Call-Request"
	case 15:
		return "Call-Clear-Request"
	default:
		return fmt.Sprintf("control_%d", t)
	}
}

// printableRun extracts the longest printable ASCII run from a binary blob,
// which is usually the client's hostname or vendor string.
func printableRun(b []byte, from int) string {
	if from >= len(b) {
		return ""
	}
	best, cur := "", strings.Builder{}
	flush := func() {
		if cur.Len() >= 4 && cur.Len() > len(best) {
			best = cur.String()
		}
		cur.Reset()
	}
	for _, c := range b[from:] {
		if c >= 0x20 && c < 0x7f {
			cur.WriteByte(c)
			continue
		}
		flush()
	}
	flush()
	return best
}

// randBytes returns n random bytes for protocol identifiers (session ids,
// SPIs). Falls back to zeros rather than failing a handshake.
func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return make([]byte, n)
	}
	return b
}
