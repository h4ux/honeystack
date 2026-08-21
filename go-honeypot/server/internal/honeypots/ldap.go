package honeypots

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

// LDAP application tags we care about (BER, class APPLICATION, constructed).
const (
	ldapBindRequest   = 0x60
	ldapBindResponse  = 0x61
	ldapUnbindRequest = 0x42
	ldapSearchRequest = 0x63
	ldapSearchDone    = 0x65
)

// NewLDAP emulates just enough LDAP to capture simple-bind credentials.
// Directory scanners bind with a DN and a cleartext password, which is the
// whole point of listening on 389.
func NewLDAP(cfg config.Service, store *eventlog.Store) *TCP {
	var t *TCP
	t = NewTCP("ldap", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		cfg := t.Cfg()
		r := bufio.NewReader(conn)
		log := func(typ string, e eventlog.Event) {
			e.Service, e.Type, e.SessionID = "ldap", typ, sessionID
			e.RemoteIP, e.RemotePort, e.LocalPort = meta.RemoteIP, meta.RemotePort, meta.LocalPort
			store.Log(e)
		}

		for {
			msg, err := readLDAPMessage(r)
			if err != nil {
				return
			}
			msgID, op, payload, err := parseLDAPMessage(msg)
			if err != nil {
				log("payload", eventlog.Event{
					Details: map[string]any{"bytes": len(msg), "hex": hex.EncodeToString(truncateBytes(msg, 64)), "error": err.Error()},
				})
				return
			}

			switch op {
			case ldapBindRequest:
				dn, password, simple := parseLDAPBind(payload)
				user := ldapShortName(dn)
				if dn == "" && password == "" {
					// Anonymous bind: still worth recording, no credentials.
					log("auth_attempt", eventlog.Event{
						Details: map[string]any{"bind": "anonymous"},
					})
					_, _ = conn.Write(ldapBindResult(msgID, 0))
					continue
				}
				if !simple {
					log("auth_attempt", eventlog.Event{
						Username: user,
						Details:  map[string]any{"dn": dn, "bind": "sasl"},
					})
					_, _ = conn.Write(ldapBindResult(msgID, 7)) // authMethodNotSupported
					continue
				}
				store.SetSessionUsername(sessionID, user)
				accepted := shouldAccept(cfg.FakeAuth, user, password)
				log(ternary(accepted, "auth_success", "login_attempt"), eventlog.Event{
					Username: user, Password: password,
					Details: map[string]any{"dn": dn, "bind": "simple", "accepted": accepted},
				})
				if accepted {
					_, _ = conn.Write(ldapBindResult(msgID, 0))
				} else {
					_, _ = conn.Write(ldapBindResult(msgID, 49)) // invalidCredentials
				}
			case ldapSearchRequest:
				base, _ := readBERString(payload)
				log("query", eventlog.Event{
					Command: "search " + base,
					Details: map[string]any{"baseDN": base},
				})
				_, _ = conn.Write(ldapResult(msgID, ldapSearchDone, 0))
			case ldapUnbindRequest:
				return
			default:
				log("payload", eventlog.Event{
					Details: map[string]any{"op": op, "bytes": len(msg)},
				})
				_, _ = conn.Write(ldapResult(msgID, ldapBindResponse, 53)) // unwillingToPerform
			}
			_ = ctx
		}
	})
	return t
}

// readLDAPMessage reads one BER SEQUENCE (tag 0x30) with a definite length.
func readLDAPMessage(r *bufio.Reader) ([]byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if tag != 0x30 {
		return nil, errors.New("not an LDAPMessage sequence")
	}
	first, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	length := int(first)
	header := []byte{tag, first}
	if first&0x80 != 0 {
		n := int(first & 0x7f)
		if n == 0 || n > 4 {
			return nil, errors.New("unsupported BER length")
		}
		lenBytes := make([]byte, n)
		if _, err := io.ReadFull(r, lenBytes); err != nil {
			return nil, err
		}
		header = append(header, lenBytes...)
		length = 0
		for _, b := range lenBytes {
			length = length<<8 | int(b)
		}
	}
	if length < 0 || length > 1<<20 {
		return nil, errors.New("LDAP message too large")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

// parseLDAPMessage returns the message id, the protocol-op tag and the bytes
// inside that op.
func parseLDAPMessage(msg []byte) (int, byte, []byte, error) {
	_, body, err := readBERElement(msg)
	if err != nil {
		return 0, 0, nil, err
	}
	// messageID INTEGER
	idTag, idVal, rest, err := readBERTagged(body)
	if err != nil || idTag != 0x02 {
		return 0, 0, nil, errors.New("bad messageID")
	}
	msgID := 0
	for _, b := range idVal {
		msgID = msgID<<8 | int(b)
	}
	opTag, opVal, _, err := readBERTagged(rest)
	if err != nil {
		return msgID, 0, nil, errors.New("bad protocolOp")
	}
	return msgID, opTag, opVal, nil
}

// parseLDAPBind pulls the DN and the simple-auth password out of a
// BindRequest: version INTEGER, name OCTET STRING, auth [0] OCTET STRING.
func parseLDAPBind(payload []byte) (dn string, password string, simple bool) {
	_, _, rest, err := readBERTagged(payload) // version
	if err != nil {
		return "", "", false
	}
	nameTag, nameVal, rest2, err := readBERTagged(rest)
	if err != nil || nameTag != 0x04 {
		return "", "", false
	}
	dn = string(nameVal)
	authTag, authVal, _, err := readBERTagged(rest2)
	if err != nil {
		return dn, "", false
	}
	if authTag == 0x80 { // [0] simple
		return dn, string(authVal), true
	}
	return dn, "", false
}

// readBERElement reads one element and returns its tag and value.
func readBERElement(b []byte) (byte, []byte, error) {
	tag, val, _, err := readBERTagged(b)
	return tag, val, err
}

// readBERTagged reads one element and also returns whatever follows it.
func readBERTagged(b []byte) (byte, []byte, []byte, error) {
	if len(b) < 2 {
		return 0, nil, nil, errors.New("short BER element")
	}
	tag := b[0]
	length := int(b[1])
	idx := 2
	if b[1]&0x80 != 0 {
		n := int(b[1] & 0x7f)
		if n == 0 || n > 4 || len(b) < 2+n {
			return 0, nil, nil, errors.New("unsupported BER length")
		}
		length = 0
		for _, x := range b[2 : 2+n] {
			length = length<<8 | int(x)
		}
		idx = 2 + n
	}
	if length < 0 || idx+length > len(b) {
		return 0, nil, nil, errors.New("BER length past end of buffer")
	}
	return tag, b[idx : idx+length], b[idx+length:], nil
}

func readBERString(b []byte) (string, error) {
	tag, val, _, err := readBERTagged(b)
	if err != nil {
		return "", err
	}
	if tag != 0x04 {
		return "", errors.New("not an octet string")
	}
	return string(val), nil
}

// ldapBindResult builds a BindResponse with the given LDAP result code.
func ldapBindResult(msgID int, code byte) []byte {
	return ldapResult(msgID, ldapBindResponse, code)
}

func ldapResult(msgID int, opTag byte, code byte) []byte {
	inner := []byte{
		0x0a, 0x01, code, // resultCode ENUMERATED
		0x04, 0x00, // matchedDN
		0x04, 0x00, // diagnosticMessage
	}
	op := append([]byte{opTag, byte(len(inner))}, inner...)
	id := []byte{0x02, 0x01, byte(msgID)}
	if msgID > 255 {
		id = []byte{0x02, 0x02, byte(msgID >> 8), byte(msgID)}
	}
	body := append(id, op...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

// ldapShortName turns "cn=admin,dc=corp,dc=local" into "admin" so the
// credential tables stay readable; the full DN stays in the details.
func ldapShortName(dn string) string {
	if dn == "" {
		return ""
	}
	first := dn
	if i := strings.Index(dn, ","); i > 0 {
		first = dn[:i]
	}
	if i := strings.Index(first, "="); i >= 0 && i+1 < len(first) {
		return strings.TrimSpace(first[i+1:])
	}
	return strings.TrimSpace(first)
}

func truncateBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}
