package honeypots

import (
	"context"
	"encoding/hex"
	"net"
	"strings"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

func NewMQTT(cfg config.Service, store *eventlog.Store) *TCP {
	return NewTCP("mqtt", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		for packets := 0; packets < 64; packets++ {
			first := make([]byte, 1)
			if _, err := readFull(conn, first); err != nil {
				return
			}
			remaining, encoded, err := readMQTTRemaining(conn)
			if err != nil || remaining > 1024*1024 {
				return
			}
			payload := make([]byte, remaining)
			if _, err := readFull(conn, payload); err != nil {
				return
			}
			packetType := first[0] >> 4
			switch packetType {
			case 1: // CONNECT
				c := parseMQTTConnect(payload)
				store.Log(eventlog.Event{
					Service: "mqtt", Type: "login_attempt", SessionID: sessionID,
					RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
					Username: c.Username, Password: c.Password,
					Details: map[string]any{
						"clientId": c.ClientID, "protocol": c.Protocol,
						"cleanSession": c.CleanSession, "keepAlive": c.KeepAlive,
						"willTopic": c.WillTopic,
					},
				})
				// Accept the fake session so publishes/subscriptions are captured.
				_, _ = conn.Write([]byte{0x20, 0x02, 0x00, 0x00})

			case 3: // PUBLISH
				topic, off, ok := mqttString(payload, 0)
				if !ok {
					return
				}
				qos := (first[0] >> 1) & 0x03
				packetID := uint16(0)
				if qos > 0 && off+2 <= len(payload) {
					packetID = uint16(payload[off])<<8 | uint16(payload[off+1])
					off += 2
				}
				body := payload[off:]
				store.Log(eventlog.Event{
					Service: "mqtt", Type: "publish", SessionID: sessionID,
					RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
					Command: topic,
					Details: map[string]any{"topic": topic, "qos": qos, "payload": string(body), "hex": hex.EncodeToString(body[:minInt(len(body), 256)])},
				})
				if qos == 1 {
					_, _ = conn.Write([]byte{0x40, 0x02, byte(packetID >> 8), byte(packetID)})
				}

			case 8: // SUBSCRIBE
				if len(payload) < 2 {
					return
				}
				packetID := payload[:2]
				var topics []string
				for off := 2; off < len(payload); {
					topic, next, ok := mqttString(payload, off)
					if !ok || next >= len(payload) {
						break
					}
					topics = append(topics, topic)
					off = next + 1 // requested QoS
				}
				store.Log(eventlog.Event{
					Service: "mqtt", Type: "subscribe", SessionID: sessionID,
					RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
					Command: strings.Join(topics, ","),
					Details: map[string]any{"topics": topics},
				})
				ack := []byte{0x90, byte(2 + len(topics)), packetID[0], packetID[1]}
				for range topics {
					ack = append(ack, 0)
				}
				_, _ = conn.Write(ack)

			case 12: // PINGREQ
				store.Log(eventlog.Event{
					Service: "mqtt", Type: "ping", SessionID: sessionID,
					RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
				})
				_, _ = conn.Write([]byte{0xd0, 0x00})
			case 14: // DISCONNECT
				return
			default:
				store.Log(eventlog.Event{
					Service: "mqtt", Type: "payload", SessionID: sessionID,
					RemoteIP: meta.RemoteIP, RemotePort: meta.RemotePort, LocalPort: meta.LocalPort,
					Details: map[string]any{"packetType": packetType, "remainingLengthBytes": encoded, "hex": hex.EncodeToString(payload[:minInt(len(payload), 256)])},
				})
			}
		}
		_ = ctx
	})
}

type mqttConnect struct {
	Protocol     string
	ClientID     string
	Username     string
	Password     string
	WillTopic    string
	CleanSession bool
	KeepAlive    int
}

func parseMQTTConnect(p []byte) mqttConnect {
	var out mqttConnect
	protocol, off, ok := mqttString(p, 0)
	if !ok || off+4 > len(p) {
		return out
	}
	out.Protocol = protocol
	off++ // protocol level
	flags := p[off]
	off++
	out.CleanSession = flags&0x02 != 0
	out.KeepAlive = int(p[off])<<8 | int(p[off+1])
	off += 2
	out.ClientID, off, _ = mqttString(p, off)
	if flags&0x04 != 0 { // will
		out.WillTopic, off, _ = mqttString(p, off)
		_, off, _ = mqttString(p, off) // will payload
	}
	if flags&0x80 != 0 {
		out.Username, off, _ = mqttString(p, off)
	}
	if flags&0x40 != 0 {
		out.Password, _, _ = mqttString(p, off)
	}
	return out
}

func mqttString(p []byte, off int) (string, int, bool) {
	if off+2 > len(p) {
		return "", off, false
	}
	n := int(p[off])<<8 | int(p[off+1])
	off += 2
	if n < 0 || off+n > len(p) {
		return "", off, false
	}
	return string(p[off : off+n]), off + n, true
}

func readMQTTRemaining(conn net.Conn) (int, int, error) {
	multiplier, value, used := 1, 0, 0
	for {
		var b [1]byte
		if _, err := readFull(conn, b[:]); err != nil {
			return 0, used, err
		}
		used++
		value += int(b[0]&127) * multiplier
		if b[0]&128 == 0 {
			return value, used, nil
		}
		if used >= 4 {
			return 0, used, net.InvalidAddrError("invalid MQTT remaining length")
		}
		multiplier *= 128
	}
}
