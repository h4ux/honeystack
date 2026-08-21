package honeypots

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

// UDP infrastructure services. All four below are abused for reflection or
// amplification, so they are scanned constantly and the useful record is
// *what* was asked for: the queried name, the SNMP community string, the
// NTP control mode, the file a TFTP client wanted.

// NewDNS emulates an open resolver (UDP/53). It answers with NXDOMAIN, which
// is enough to look alive without ever becoming a usable amplifier.
func NewDNS(name string, cfg config.Service, store *eventlog.Store) *UDP {
	return NewUDPProto(name, cfg, store, func(payload []byte, meta ConnMeta) UDPReply {
		if len(payload) < 12 {
			return UDPReply{Type: "payload", Details: map[string]any{"bytes": len(payload)}}
		}
		id := binary.BigEndian.Uint16(payload[0:2])
		flags := binary.BigEndian.Uint16(payload[2:4])
		questions := binary.BigEndian.Uint16(payload[4:6])
		qname, qtype, qclass, ok := parseDNSQuestion(payload)
		details := map[string]any{
			"id": id, "questions": questions, "bytes": len(payload),
			"recursionDesired": flags&0x0100 != 0,
			"opcode":           (flags >> 11) & 0x0f,
		}
		if ok {
			details["name"] = qname
			details["type"] = dnsType(qtype)
			details["class"] = qclass
			// ANY/TXT queries for known amplifier domains are the fingerprint
			// of a reflection attack using us as the reflector.
			if qtype == 255 || qtype == 16 {
				details["amplificationCandidate"] = true
			}
		}
		cmd := "dns query"
		if ok {
			cmd = fmt.Sprintf("%s %s", dnsType(qtype), qname)
		}
		return UDPReply{
			Type:     "query",
			Command:  cmd,
			Details:  details,
			Response: dnsNXDomain(payload),
		}
	})
}

// parseDNSQuestion walks the QNAME labels of the first question.
func parseDNSQuestion(msg []byte) (string, uint16, uint16, bool) {
	if len(msg) < 13 {
		return "", 0, 0, false
	}
	var labels []string
	i := 12
	for i < len(msg) {
		l := int(msg[i])
		if l == 0 {
			i++
			break
		}
		if l&0xc0 != 0 { // compression pointer: not valid in a question
			return "", 0, 0, false
		}
		if i+1+l > len(msg) {
			return "", 0, 0, false
		}
		labels = append(labels, string(msg[i+1:i+1+l]))
		i += 1 + l
		if len(labels) > 32 {
			break
		}
	}
	if i+4 > len(msg) {
		return strings.Join(labels, "."), 0, 0, len(labels) > 0
	}
	qtype := binary.BigEndian.Uint16(msg[i : i+2])
	qclass := binary.BigEndian.Uint16(msg[i+2 : i+4])
	return strings.Join(labels, "."), qtype, qclass, true
}

// dnsNXDomain echoes the question back with rcode 3 (name error).
func dnsNXDomain(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	out := make([]byte, len(query))
	copy(out, query)
	// QR=1, RD copied, RA=1, rcode=3
	flags := binary.BigEndian.Uint16(query[2:4])
	flags = 0x8000 | (flags & 0x0100) | 0x0080 | 0x0003
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[6:8], 0)  // answers
	binary.BigEndian.PutUint16(out[8:10], 0) // authority
	binary.BigEndian.PutUint16(out[10:12], 0)
	return out
}

func dnsType(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 43:
		return "DS"
	case 48:
		return "DNSKEY"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// NewSNMP emulates an SNMP v1/v2c agent (UDP/161). The community string is
// the credential here, and "public" sweeps are ceaseless.
func NewSNMP(name string, cfg config.Service, store *eventlog.Store) *UDP {
	return NewUDPProto(name, cfg, store, func(payload []byte, meta ConnMeta) UDPReply {
		version, community, pduType, oid, ok := parseSNMP(payload)
		if !ok {
			return UDPReply{
				Type:    "payload",
				Command: "snmp malformed",
				Details: map[string]any{"bytes": len(payload)},
			}
		}
		details := map[string]any{
			"version": snmpVersion(version), "community": community,
			"pdu": snmpPDU(pduType), "bytes": len(payload),
		}
		if oid != "" {
			details["oid"] = oid
		}
		if pduType == 0xa5 {
			// GETBULK with a large max-repetitions is the amplification move.
			details["amplificationCandidate"] = true
		}
		// The community string is a password: log it as one so it shows up in
		// the credential rankings.
		return UDPReply{
			Type:     "login_attempt",
			Command:  fmt.Sprintf("%s %s %s", snmpVersion(version), snmpPDU(pduType), oid),
			Username: "community",
			Password: community,
			Details:  details,
			Response: snmpResponse(payload),
		}
	})
}

// parseSNMP pulls version, community, PDU type and the first OID out of a
// v1/v2c message using a minimal BER walk.
func parseSNMP(msg []byte) (int, string, byte, string, bool) {
	_, body, err := readBERElement(msg)
	if err != nil {
		return 0, "", 0, "", false
	}
	verTag, verVal, rest, err := readBERTagged(body)
	if err != nil || verTag != 0x02 || len(verVal) == 0 {
		return 0, "", 0, "", false
	}
	version := int(verVal[len(verVal)-1])
	commTag, commVal, rest2, err := readBERTagged(rest)
	if err != nil || commTag != 0x04 {
		return version, "", 0, "", false
	}
	pduTag, pduVal, _, err := readBERTagged(rest2)
	if err != nil {
		return version, string(commVal), 0, "", true
	}
	oid := firstOID(pduVal)
	return version, string(commVal), pduTag, oid, true
}

// firstOID finds the first OBJECT IDENTIFIER (tag 0x06) in a PDU body.
func firstOID(b []byte) string {
	rest := b
	for len(rest) >= 2 {
		tag, val, next, err := readBERTagged(rest)
		if err != nil {
			return ""
		}
		if tag == 0x06 {
			return decodeOID(val)
		}
		// Descend into constructed elements (sequences, varbind lists).
		if tag&0x20 != 0 || tag == 0x30 {
			if oid := firstOID(val); oid != "" {
				return oid
			}
		}
		rest = next
	}
	return ""
}

func decodeOID(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := []string{fmt.Sprintf("%d", b[0]/40), fmt.Sprintf("%d", b[0]%40)}
	var acc uint64
	for _, c := range b[1:] {
		acc = acc<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			parts = append(parts, fmt.Sprintf("%d", acc))
			acc = 0
		}
	}
	return strings.Join(parts, ".")
}

func snmpVersion(v int) string {
	switch v {
	case 0:
		return "SNMPv1"
	case 1:
		return "SNMPv2c"
	case 3:
		return "SNMPv3"
	default:
		return fmt.Sprintf("SNMPv?%d", v)
	}
}

func snmpPDU(t byte) string {
	switch t {
	case 0xa0:
		return "GET"
	case 0xa1:
		return "GETNEXT"
	case 0xa2:
		return "RESPONSE"
	case 0xa3:
		return "SET"
	case 0xa5:
		return "GETBULK"
	case 0xa6:
		return "INFORM"
	case 0xa7:
		return "TRAPv2"
	case 0xa4:
		return "TRAP"
	default:
		return fmt.Sprintf("pdu_0x%02x", t)
	}
}

// snmpResponse turns a request into a response by flipping the PDU tag.
// The varbinds come back unchanged, so the reply is never larger than the
// request — a live-looking agent that is useless for amplification.
func snmpResponse(request []byte) []byte {
	if len(request) < 2 || request[0] != 0x30 {
		return nil
	}
	out := make([]byte, len(request))
	copy(out, request)
	// Walk to the PDU element and rewrite its tag in place.
	_, body, err := readBERElement(out)
	if err != nil {
		return nil
	}
	offset := len(out) - len(body)
	_, verVal, rest, err := readBERTagged(body)
	if err != nil {
		return nil
	}
	_, commVal, pdu, err := readBERTagged(rest)
	if err != nil || len(pdu) == 0 {
		return nil
	}
	pduIdx := offset + (len(body) - len(pdu))
	_ = verVal
	_ = commVal
	if pduIdx < 0 || pduIdx >= len(out) {
		return nil
	}
	if out[pduIdx] == 0xa2 { // already a response: ignore it
		return nil
	}
	out[pduIdx] = 0xa2
	return out
}

// NewNTP emulates an NTP server (UDP/123), including the mode 7 control
// requests (monlist and friends) used for amplification.
func NewNTP(name string, cfg config.Service, store *eventlog.Store) *UDP {
	return NewUDPProto(name, cfg, store, func(payload []byte, meta ConnMeta) UDPReply {
		if len(payload) < 1 {
			return UDPReply{}
		}
		flags := payload[0]
		mode := flags & 0x07
		version := (flags >> 3) & 0x07
		details := map[string]any{
			"mode": mode, "modeName": ntpMode(mode), "version": version, "bytes": len(payload),
		}
		typ := "query"
		if mode == 7 {
			// mode 7 = private/control. This is the monlist family: pure
			// amplification. Never answer it.
			typ = "amplification_attempt"
			details["amplificationCandidate"] = true
			if len(payload) >= 4 {
				details["requestCode"] = payload[3]
			}
			return UDPReply{
				Type:    typ,
				Command: "ntp mode 7 (private/monlist)",
				Details: details,
			}
		}
		if mode == 6 {
			details["amplificationCandidate"] = true
			return UDPReply{Type: "amplification_attempt", Command: "ntp mode 6 (control)", Details: details}
		}
		return UDPReply{
			Type:     typ,
			Command:  "ntp " + ntpMode(mode),
			Details:  details,
			Response: ntpServerReply(payload),
		}
	})
}

func ntpMode(m byte) string {
	switch m {
	case 1:
		return "symmetric_active"
	case 2:
		return "symmetric_passive"
	case 3:
		return "client"
	case 4:
		return "server"
	case 5:
		return "broadcast"
	case 6:
		return "control"
	case 7:
		return "private"
	default:
		return "reserved"
	}
}

// ntpServerReply answers a client request (mode 3) with a plausible mode 4
// packet so the peer sees a working time server.
func ntpServerReply(req []byte) []byte {
	if len(req) < 48 {
		return nil
	}
	out := make([]byte, 48)
	out[0] = 0x24 // LI 0, VN 4, mode 4 (server)
	out[1] = 3    // stratum 3
	out[2] = 6    // poll
	out[3] = 0xec // precision
	copy(out[12:16], []byte("LOCL"))
	// NTP timestamps are seconds since 1900.
	const epochOffset = 2208988800
	now := uint32(time.Now().Unix() + epochOffset)
	binary.BigEndian.PutUint32(out[16:20], now-30) // reference
	copy(out[24:32], req[40:48])                   // originate = client transmit
	binary.BigEndian.PutUint32(out[32:36], now)    // receive
	binary.BigEndian.PutUint32(out[40:44], now)    // transmit
	return out
}

// NewTFTP emulates a TFTP server (UDP/69). Exposed TFTP leaks router
// configs; the file name in the read request is the whole story.
func NewTFTP(name string, cfg config.Service, store *eventlog.Store) *UDP {
	return NewUDPProto(name, cfg, store, func(payload []byte, meta ConnMeta) UDPReply {
		if len(payload) < 4 {
			return UDPReply{Type: "payload", Details: map[string]any{"bytes": len(payload)}}
		}
		opcode := binary.BigEndian.Uint16(payload[0:2])
		parts := strings.Split(strings.TrimRight(string(payload[2:]), "\x00"), "\x00")
		filename, mode := "", ""
		if len(parts) > 0 {
			filename = parts[0]
		}
		if len(parts) > 1 {
			mode = parts[1]
		}
		details := map[string]any{
			"opcode": opcode, "opcodeName": tftpOpcode(opcode),
			"filename": filename, "mode": mode, "bytes": len(payload),
		}
		typ := "payload"
		switch opcode {
		case 1:
			typ = "query" // read request: someone fishing for config files
		case 2:
			typ = "upload_attempt" // write request: someone dropping a file
		}
		return UDPReply{
			Type:    typ,
			Command: fmt.Sprintf("%s %s", tftpOpcode(opcode), filename),
			Details: details,
			// Error 1 = file not found; error 2 = access violation for writes.
			Response: tftpError(ternary(opcode == 2, "2", "1"), ternary(opcode == 2, "Access violation", "File not found")),
		}
	})
}

func tftpOpcode(o uint16) string {
	switch o {
	case 1:
		return "RRQ"
	case 2:
		return "WRQ"
	case 3:
		return "DATA"
	case 4:
		return "ACK"
	case 5:
		return "ERROR"
	case 6:
		return "OACK"
	default:
		return fmt.Sprintf("opcode_%d", o)
	}
}

func tftpError(code, message string) []byte {
	out := []byte{0x00, 0x05, 0x00, code[0] - '0'}
	out = append(out, []byte(message)...)
	return append(out, 0x00)
}

// NewSIP emulates a SIP endpoint (UDP or TCP 5060). VoIP fraud scanners
// hammer it with REGISTER/OPTIONS looking for a PBX they can place calls
// through, and their Authorization headers carry real credentials.
func NewSIP(name string, cfg config.Service, store *eventlog.Store) *UDP {
	return NewUDPProto(name, cfg, store, func(payload []byte, meta ConnMeta) UDPReply {
		text := string(payload)
		method, uri, headers := parseSIP(text)
		user, realm, response := sipCredentials(headers)
		details := map[string]any{
			"method": method, "uri": uri,
			"userAgent": headers["user-agent"], "from": headers["from"], "to": headers["to"],
			"bytes": len(payload),
		}
		if realm != "" {
			details["realm"] = realm
		}
		if method == "INVITE" {
			details["tollFraudCandidate"] = true
		}
		typ := "request"
		switch method {
		case "REGISTER":
			typ = ternary(user != "", "login_attempt", "request")
		case "INVITE", "OPTIONS", "SUBSCRIBE":
			typ = "request"
		case "":
			return UDPReply{Type: "payload", Command: truncateStr(strings.TrimSpace(text), 120), Details: details}
		}
		return UDPReply{
			Type:     typ,
			Command:  strings.TrimSpace(method + " " + uri),
			Username: user,
			Password: response,
			Details:  details,
			Response: []byte(sipUnauthorized(text, headers)),
		}
	})
}

// NewSIPTCP is the TCP flavour of the SIP emulator. Same parsing, but SIP
// over TCP arrives as a stream of request blocks terminated by a blank line.
func NewSIPTCP(cfg config.Service, store *eventlog.Store) *TCP {
	var t *TCP
	t = NewTCP("sip-tcp", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		r := bufio.NewReader(conn)
		log := func(typ string, e eventlog.Event) {
			e.Service, e.Type, e.SessionID = "sip-tcp", typ, sessionID
			e.RemoteIP, e.RemotePort, e.LocalPort = meta.RemoteIP, meta.RemotePort, meta.LocalPort
			store.Log(e)
		}
		for {
			var block strings.Builder
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				block.WriteString(line)
				if strings.TrimSpace(line) == "" || block.Len() > 64*1024 {
					break
				}
			}
			text := block.String()
			method, uri, headers := parseSIP(text)
			user, realm, response := sipCredentials(headers)
			details := map[string]any{
				"method": method, "uri": uri,
				"userAgent": headers["user-agent"], "from": headers["from"], "to": headers["to"],
				"bytes": len(text),
			}
			if realm != "" {
				details["realm"] = realm
			}
			if method == "INVITE" {
				details["tollFraudCandidate"] = true
			}
			if method == "" {
				log("payload", eventlog.Event{Command: truncateStr(strings.TrimSpace(text), 120), Details: details})
				return
			}
			if user != "" {
				store.SetSessionUsername(sessionID, user)
			}
			log(ternary(method == "REGISTER" && user != "", "login_attempt", "request"), eventlog.Event{
				Username: user, Password: response,
				Command: strings.TrimSpace(method + " " + uri),
				Details: details,
			})
			_, _ = conn.Write([]byte(sipUnauthorized(text, headers)))
			_ = ctx
		}
	})
	return t
}

func parseSIP(text string) (string, string, map[string]string) {
	headers := map[string]string{}
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return "", "", headers
	}
	fields := strings.Fields(strings.TrimSpace(lines[0]))
	method, uri := "", ""
	if len(fields) >= 2 && strings.HasPrefix(strings.ToUpper(fields[0]), strings.ToUpper(fields[0])) {
		method = strings.ToUpper(fields[0])
		uri = fields[1]
	}
	// Only real SIP methods count; anything else is junk on the port.
	switch method {
	case "REGISTER", "INVITE", "OPTIONS", "ACK", "BYE", "CANCEL", "SUBSCRIBE",
		"NOTIFY", "PUBLISH", "INFO", "MESSAGE", "REFER", "UPDATE", "PRACK":
	default:
		method = ""
	}
	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		headers[strings.ToLower(strings.TrimSpace(line[:idx]))] = strings.TrimSpace(line[idx+1:])
	}
	return method, uri, headers
}

// sipCredentials reads username/realm/response out of a digest Authorization
// header. The response is an MD5 digest, not the password, but it is still a
// credential attempt worth ranking.
func sipCredentials(headers map[string]string) (string, string, string) {
	auth := headers["authorization"]
	if auth == "" {
		auth = headers["proxy-authorization"]
	}
	if auth == "" {
		// Fall back to the From header, which carries the extension being
		// probed even without auth.
		from := headers["from"]
		if i := strings.Index(from, "sip:"); i >= 0 {
			rest := from[i+4:]
			if j := strings.IndexAny(rest, "@>;"); j > 0 {
				return rest[:j], "", ""
			}
		}
		return "", "", ""
	}
	get := func(key string) string {
		idx := strings.Index(strings.ToLower(auth), key+"=")
		if idx < 0 {
			return ""
		}
		rest := auth[idx+len(key)+1:]
		rest = strings.TrimPrefix(rest, "\"")
		if j := strings.IndexAny(rest, "\","); j >= 0 {
			rest = rest[:j]
		}
		return rest
	}
	return get("username"), get("realm"), get("response")
}

func sipUnauthorized(request string, headers map[string]string) string {
	via := headers["via"]
	callID := headers["call-id"]
	from := headers["from"]
	to := headers["to"]
	cseq := headers["cseq"]
	nonce := eventlog.RandID(8)
	return "SIP/2.0 401 Unauthorized\r\n" +
		"Via: " + via + "\r\n" +
		"From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: " + cseq + "\r\n" +
		"WWW-Authenticate: Digest realm=\"asterisk\", nonce=\"" + nonce + "\", algorithm=MD5\r\n" +
		"Server: Asterisk PBX 20.5.0\r\n" +
		"Content-Length: 0\r\n\r\n"
}
