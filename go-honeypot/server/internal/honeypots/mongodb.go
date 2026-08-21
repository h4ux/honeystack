package honeypots

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"

	"github.com/example/honeypot/internal/config"
	"github.com/example/honeypot/internal/eventlog"
)

const (
	mongoOpReply = 1
	mongoOpQuery = 2004
	mongoOpMsg   = 2013
)

func NewMongoDB(cfg config.Service, store *eventlog.Store) *TCP {
	return NewTCP("mongodb", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		for packets := 0; packets < 8; packets++ {
			header := make([]byte, 16)
			if _, err := readFull(conn, header); err != nil {
				return
			}
			length := int(int32(binary.LittleEndian.Uint32(header[0:4])))
			requestID := int32(binary.LittleEndian.Uint32(header[4:8]))
			opcode := int32(binary.LittleEndian.Uint32(header[12:16]))
			if length < 16 || length > 16*1024*1024 {
				return
			}
			payload := make([]byte, length-16)
			if _, err := readFull(conn, payload); err != nil {
				return
			}
			stringsFound := printableRuns(payload)
			command := mongoCommandName(stringsFound)
			typ := "command"
			user, password := mongoCredentials(stringsFound)
			if user != "" || password != "" || strings.Contains(strings.ToLower(command), "sasl") {
				typ = "login_attempt"
			}
			store.Log(eventlog.Event{
				Service: "mongodb", Type: typ, SessionID: sessionID,
				RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
				Username: user, Password: password, Command: command,
				Details: map[string]any{
					"opcode": opcode, "length": length, "strings": stringsFound,
					"hex": hex.EncodeToString(payload[:minInt(len(payload), 256)]),
				},
			})

			switch opcode {
			case mongoOpMsg:
				doc := mongoHelloDocument(firstNonEmpty(cfg.ServerVersion, "7.0.14"))
				reply := make([]byte, 5+len(doc))
				// OP_MSG flags (4) + section kind 0 (1) + document.
				copy(reply[5:], doc)
				if _, err := conn.Write(mongoPacket(requestID, mongoOpMsg, reply)); err != nil {
					return
				}
			case mongoOpQuery:
				doc := mongoHelloDocument(firstNonEmpty(cfg.ServerVersion, "7.0.14"))
				reply := make([]byte, 20+len(doc))
				binary.LittleEndian.PutUint32(reply[0:4], 0) // flags
				// cursor ID 8 bytes and startingFrom remain zero.
				binary.LittleEndian.PutUint32(reply[16:20], 1)
				copy(reply[20:], doc)
				if _, err := conn.Write(mongoPacket(requestID, mongoOpReply, reply)); err != nil {
					return
				}
			default:
				return
			}
		}
		_ = ctx
	})
}

func mongoPacket(responseTo int32, opcode int32, payload []byte) []byte {
	out := make([]byte, 16+len(payload))
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(out)))
	binary.LittleEndian.PutUint32(out[4:8], 1)
	binary.LittleEndian.PutUint32(out[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(out[12:16], uint32(opcode))
	copy(out[16:], payload)
	return out
}

func mongoHelloDocument(version string) []byte {
	var fields []byte
	fields = bsonBool(fields, "isWritablePrimary", true)
	fields = bsonBool(fields, "ismaster", true)
	fields = bsonInt32(fields, "maxBsonObjectSize", 16777216)
	fields = bsonInt32(fields, "maxMessageSizeBytes", 48000000)
	fields = bsonInt32(fields, "maxWriteBatchSize", 100000)
	fields = bsonInt32(fields, "minWireVersion", 0)
	fields = bsonInt32(fields, "maxWireVersion", 21)
	fields = bsonInt32(fields, "logicalSessionTimeoutMinutes", 30)
	fields = bsonString(fields, "me", "mongo-prod-01:27017")
	fields = bsonString(fields, "setName", "rs0")
	fields = bsonString(fields, "version", version)
	fields = bsonDouble(fields, "ok", 1)
	out := make([]byte, 4, 5+len(fields))
	out = append(out, fields...)
	out = append(out, 0)
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(out)))
	return out
}

func bsonBool(dst []byte, key string, v bool) []byte {
	dst = append(dst, 0x08)
	dst = appendCString(dst, key)
	if v {
		return append(dst, 1)
	}
	return append(dst, 0)
}
func bsonInt32(dst []byte, key string, v int32) []byte {
	dst = append(dst, 0x10)
	dst = appendCString(dst, key)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	return append(dst, b[:]...)
}
func bsonString(dst []byte, key, v string) []byte {
	dst = append(dst, 0x02)
	dst = appendCString(dst, key)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(len(v)+1))
	dst = append(dst, b[:]...)
	dst = append(dst, v...)
	return append(dst, 0)
}
func bsonDouble(dst []byte, key string, v float64) []byte {
	dst = append(dst, 0x01)
	dst = appendCString(dst, key)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], 0x3ff0000000000000) // 1.0
	return append(dst, b[:]...)
}
func appendCString(dst []byte, s string) []byte {
	dst = append(dst, s...)
	return append(dst, 0)
}

func mongoCommandName(runs []string) string {
	known := []string{"hello", "ismaster", "isMaster", "saslStart", "saslContinue", "ping", "buildInfo", "listDatabases", "find", "aggregate", "insert", "update", "delete"}
	for _, run := range runs {
		for _, cmd := range known {
			if strings.Contains(run, cmd) {
				return cmd
			}
		}
	}
	if len(runs) > 0 {
		return runs[0]
	}
	return ""
}

func mongoCredentials(runs []string) (string, string) {
	joined := strings.Join(runs, ",")
	// SCRAM client-first messages contain n=<user>; clients never send the
	// clear password, so retain the proof/payload as the credential evidence.
	user := ""
	if i := strings.Index(joined, "n="); i >= 0 {
		rest := joined[i+2:]
		if end := strings.IndexAny(rest, ",\x00"); end >= 0 {
			user = rest[:end]
		} else {
			user = rest
		}
	}
	proof := ""
	if i := strings.Index(joined, "p="); i >= 0 {
		proof = joined[i+2:]
		if end := strings.IndexAny(proof, ",\x00"); end >= 0 {
			proof = proof[:end]
		}
		if len(proof) > 128 {
			proof = proof[:128]
		}
	}
	return user, proof
}
