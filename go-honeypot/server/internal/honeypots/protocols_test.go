package honeypots

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseSNMPv2c(t *testing.T) {
	// SNMPv2c GET for 1.3.6.1.2.1.1.5.0 with community "public".
	req, err := hex.DecodeString("302902010104067075626c6963a01c020455f6d1e2020100020100300e300c06082b060102010105000500")
	if err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	version, community, pdu, oid, ok := parseSNMP(req)
	if !ok {
		t.Fatal("parseSNMP reported failure")
	}
	if version != 1 {
		t.Errorf("version = %d, want 1 (v2c)", version)
	}
	if community != "public" {
		t.Errorf("community = %q, want public", community)
	}
	if pdu != 0xa0 {
		t.Errorf("pdu = 0x%02x, want 0xa0 (GET)", pdu)
	}
	if oid != "1.3.6.1.2.1.1.5.0" {
		t.Errorf("oid = %s, want 1.3.6.1.2.1.1.5.0", oid)
	}

	resp := snmpResponse(req)
	if len(resp) != len(req) {
		t.Fatalf("response length %d, want %d (an amplifying reply would be larger)", len(resp), len(req))
	}
	_, _, respPDU, _, ok := parseSNMP(resp)
	if !ok || respPDU != 0xa2 {
		t.Errorf("response pdu = 0x%02x, want 0xa2 (RESPONSE)", respPDU)
	}
	// Feeding a response back in must not produce another response.
	if snmpResponse(resp) != nil {
		t.Error("snmpResponse echoed a response packet")
	}
}

func TestParseLDAPSimpleBind(t *testing.T) {
	dn, pw := "cn=admin,dc=corp,dc=local", "Secret123!"
	inner := []byte{0x02, 0x01, 0x03}
	inner = append(inner, 0x04, byte(len(dn)))
	inner = append(inner, dn...)
	inner = append(inner, 0x80, byte(len(pw)))
	inner = append(inner, pw...)
	op := append([]byte{ldapBindRequest, byte(len(inner))}, inner...)
	body := append([]byte{0x02, 0x01, 0x07}, op...)
	msg := append([]byte{0x30, byte(len(body))}, body...)

	msgID, opTag, payload, err := parseLDAPMessage(msg)
	if err != nil {
		t.Fatalf("parseLDAPMessage: %v", err)
	}
	if msgID != 7 {
		t.Errorf("messageID = %d, want 7", msgID)
	}
	if opTag != ldapBindRequest {
		t.Errorf("op = 0x%02x, want 0x%02x", opTag, ldapBindRequest)
	}
	gotDN, gotPW, simple := parseLDAPBind(payload)
	if !simple {
		t.Error("bind not recognised as simple auth")
	}
	if gotDN != dn || gotPW != pw {
		t.Errorf("bind = (%q, %q), want (%q, %q)", gotDN, gotPW, dn, pw)
	}
	if short := ldapShortName(dn); short != "admin" {
		t.Errorf("ldapShortName = %q, want admin", short)
	}

	// The reply must be a well-formed BindResponse carrying our result code.
	resp := ldapBindResult(msgID, 49)
	id, tag, inner2, err := parseLDAPMessage(resp)
	if err != nil || id != 7 || tag != ldapBindResponse {
		t.Fatalf("bind response = (%d, 0x%02x, %v)", id, tag, err)
	}
	if len(inner2) < 3 || inner2[2] != 49 {
		t.Errorf("result code = %v, want 49", inner2)
	}
}

func TestParseDNSQuestion(t *testing.T) {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(msg[4:6], 1)
	for _, label := range []string{"isc", "org"} {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00)
	msg = append(msg, 0x00, 0xff, 0x00, 0x01) // ANY / IN

	name, qtype, qclass, ok := parseDNSQuestion(msg)
	if !ok {
		t.Fatal("question not parsed")
	}
	if name != "isc.org" {
		t.Errorf("name = %q, want isc.org", name)
	}
	if dnsType(qtype) != "ANY" || qclass != 1 {
		t.Errorf("type/class = %s/%d, want ANY/1", dnsType(qtype), qclass)
	}

	resp := dnsNXDomain(msg)
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 {
		t.Error("response bit not set")
	}
	if flags&0x000f != 3 {
		t.Errorf("rcode = %d, want 3 (NXDOMAIN)", flags&0x000f)
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 0 {
		t.Error("NXDOMAIN reply must carry no answers")
	}
}

func TestSMTPAndProxyCredentialDecoding(t *testing.T) {
	if got := decodeB64("c3BhbW1lcg=="); got != "spammer" {
		t.Errorf("decodeB64 = %q, want spammer", got)
	}
	if got := trimAddress("FROM:<bot@evil.test> SIZE=42"); got != "bot@evil.test" {
		t.Errorf("trimAddress = %q, want bot@evil.test", got)
	}
	user, pass := splitImapLogin(`"root" "toor"`)
	if user != "root" || pass != "toor" {
		t.Errorf("splitImapLogin = (%q, %q), want (root, toor)", user, pass)
	}
	// Proxy-Authorization: Basic proxyuser:proxypass
	headers := map[string]string{"proxy-authorization": "Basic cHJveHl1c2VyOnByb3h5cGFzcw=="}
	u, p := proxyCredentials(headers)
	if u != "proxyuser" || p != "proxypass" {
		t.Errorf("proxyCredentials = (%q, %q), want (proxyuser, proxypass)", u, p)
	}
	if intent := proxyIntent(25); intent != "spam relay" {
		t.Errorf("proxyIntent(25) = %q, want spam relay", intent)
	}
}

func TestSIPCredentialsAndResponse(t *testing.T) {
	req := "REGISTER sip:pbx.local SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK1\r\n" +
		"From: <sip:1001@pbx.local>;tag=1\r\nTo: <sip:1001@pbx.local>\r\n" +
		"Call-ID: abc123\r\nCSeq: 1 REGISTER\r\n" +
		`Authorization: Digest username="1001", realm="asterisk", nonce="x", response="deadbeef"` + "\r\n\r\n"
	method, uri, headers := parseSIP(req)
	if method != "REGISTER" || uri != "sip:pbx.local" {
		t.Errorf("parseSIP = (%q, %q)", method, uri)
	}
	user, realm, resp := sipCredentials(headers)
	if user != "1001" || realm != "asterisk" || resp != "deadbeef" {
		t.Errorf("sipCredentials = (%q, %q, %q)", user, realm, resp)
	}
	reply := sipUnauthorized(req, headers)
	if !strings.HasPrefix(reply, "SIP/2.0 401 Unauthorized") {
		t.Errorf("reply = %q", reply[:40])
	}
	if !strings.Contains(reply, "Call-ID: abc123") {
		t.Error("reply must echo the Call-ID")
	}

	// Junk on the port must not be mistaken for a SIP request.
	if m, _, _ := parseSIP("GET / HTTP/1.1\r\n\r\n"); m != "" {
		t.Errorf("parseSIP accepted non-SIP method %q", m)
	}
}

func TestADBFraming(t *testing.T) {
	payload := []byte("shell:id\x00")
	msg := adbMessage(adbOPEN, 5, 0, payload)
	if len(msg) != 24+len(payload) {
		t.Fatalf("message length = %d", len(msg))
	}
	if got := binary.LittleEndian.Uint32(msg[0:4]); got != adbOPEN {
		t.Errorf("command = 0x%08x, want 0x%08x", got, adbOPEN)
	}
	if got := binary.LittleEndian.Uint32(msg[12:16]); int(got) != len(payload) {
		t.Errorf("data length = %d, want %d", got, len(payload))
	}
	magic := binary.LittleEndian.Uint32(msg[20:24])
	if magic != adbOPEN^0xffffffff {
		t.Error("magic must be the command XOR 0xffffffff")
	}
	if kind := adbStreamKind("shell:id"); kind != "shell" {
		t.Errorf("adbStreamKind = %q, want shell", kind)
	}
	if out := adbFakeOutput("shell:id"); !strings.Contains(out, "uid=0(root)") {
		t.Errorf("adbFakeOutput = %q", out)
	}
}

func TestPPTPAndOpenVPNReplies(t *testing.T) {
	reply := pptpStartReply()
	if binary.BigEndian.Uint16(reply[0:2]) != 156 {
		t.Errorf("length field = %d, want 156", binary.BigEndian.Uint16(reply[0:2]))
	}
	if binary.BigEndian.Uint32(reply[4:8]) != 0x1a2b3c4d {
		t.Error("magic cookie mismatch")
	}
	if binary.BigEndian.Uint16(reply[8:10]) != 2 {
		t.Error("control type must be Start-Control-Connection-Reply")
	}

	client := append([]byte{7 << 3}, []byte{1, 2, 3, 4, 5, 6, 7, 8, 0}...)
	out := openvpnServerReset(client)
	if out[0]>>3 != 8 {
		t.Errorf("opcode = %d, want 8 (hard reset server v2)", out[0]>>3)
	}
	// The client's session id must come back so the peer keeps talking.
	if !strings.Contains(string(out), string(client[1:9])) {
		t.Error("server reset does not echo the client session id")
	}
}

func TestTFTPErrorPacket(t *testing.T) {
	pkt := tftpError("1", "File not found")
	if binary.BigEndian.Uint16(pkt[0:2]) != 5 {
		t.Error("opcode must be ERROR (5)")
	}
	if binary.BigEndian.Uint16(pkt[2:4]) != 1 {
		t.Errorf("error code = %d, want 1", binary.BigEndian.Uint16(pkt[2:4]))
	}
	if pkt[len(pkt)-1] != 0x00 {
		t.Error("error message must be NUL terminated")
	}
}

func TestPrintableRun(t *testing.T) {
	blob := append([]byte{0x00, 0x01, 0xff}, []byte("attacker-host")...)
	blob = append(blob, 0x00, 0x02)
	if got := printableRun(blob, 0); got != "attacker-host" {
		t.Errorf("printableRun = %q", got)
	}
	if got := printableRun([]byte{0x00, 0x01}, 0); got != "" {
		t.Errorf("printableRun on binary = %q, want empty", got)
	}
}
