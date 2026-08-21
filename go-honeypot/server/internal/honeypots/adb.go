package honeypots

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
)

// Android Debug Bridge wire commands (little-endian ASCII tags).
const (
	adbCNXN = 0x4e584e43 // "CNXN"
	adbOPEN = 0x4e45504f // "OPEN"
	adbOKAY = 0x59414b4f // "OKAY"
	adbWRTE = 0x45545257 // "WRTE"
	adbCLSE = 0x45534c43 // "CLSE"
	adbAUTH = 0x48545541 // "AUTH"
	adbSYNC = 0x434e5953 // "SYNC"
)

// NewADB emulates an unauthenticated Android Debug Bridge daemon on 5555.
// Worm families (ADB.Miner and friends) scan for it constantly and drop
// their payload through `shell:` streams, so the commands they send are the
// interesting artefact. Nothing is executed.
func NewADB(cfg config.Service, store *eventlog.Store) *TCP {
	var t *TCP
	t = NewTCP("adb", cfg, store, func(ctx context.Context, conn net.Conn, sessionID string, meta ConnMeta) {
		cfg := t.Cfg()
		banner := cfg.Banner
		if banner == "" {
			model := cfg.Hostname
			if model == "" {
				model = "generic_x86"
			}
			banner = "device::ro.product.name=" + model + ";ro.product.model=" + model +
				";ro.product.device=" + model + ";features=cmd,stat_v2,shell_v2\x00"
		}
		log := func(typ string, e eventlog.Event) {
			e.Service, e.Type, e.SessionID = "adb", typ, sessionID
			e.RemoteIP, e.RemotePort, e.LocalPort = meta.RemoteIP, meta.RemotePort, meta.LocalPort
			store.Log(e)
		}

		var localID uint32 = 1
		for {
			cmd, arg0, arg1, payload, err := readADBMessage(conn)
			if err != nil {
				return
			}
			switch cmd {
			case adbCNXN:
				log("client_hello", eventlog.Event{
					Command: strings.TrimRight(string(payload), "\x00"),
					Details: map[string]any{
						"version": arg0, "maxdata": arg1,
						"identity": strings.TrimRight(string(payload), "\x00"),
					},
				})
				// Version 0x01000000, 256KB max payload, then our banner.
				_, _ = conn.Write(adbMessage(adbCNXN, 0x01000000, 256*1024, []byte(banner)))
			case adbAUTH:
				// Real devices challenge here; an open device never does, and
				// pretending to be open is the point.
				log("auth_attempt", eventlog.Event{
					Details: map[string]any{"type": arg0, "bytes": len(payload)},
				})
				_, _ = conn.Write(adbMessage(adbCNXN, 0x01000000, 256*1024, []byte(banner)))
			case adbOPEN:
				dest := strings.TrimRight(string(payload), "\x00")
				remoteID := arg0
				typ := "exec"
				if !strings.HasPrefix(dest, "shell") {
					typ = "command"
				}
				log(typ, eventlog.Event{
					Command: dest,
					Details: map[string]any{"stream": adbStreamKind(dest), "destination": dest},
				})
				_, _ = conn.Write(adbMessage(adbOKAY, localID, remoteID, nil))
				if out := adbFakeOutput(dest); out != "" {
					_, _ = conn.Write(adbMessage(adbWRTE, localID, remoteID, []byte(out)))
				}
				_, _ = conn.Write(adbMessage(adbCLSE, localID, remoteID, nil))
				localID++
			case adbWRTE:
				text := strings.TrimRight(string(payload), "\x00")
				if strings.TrimSpace(text) != "" {
					log("command", eventlog.Event{
						Command: text,
						Details: map[string]any{"stream": "write", "bytes": len(payload)},
					})
				}
				_, _ = conn.Write(adbMessage(adbOKAY, arg1, arg0, nil))
			case adbSYNC:
				log("payload", eventlog.Event{Details: map[string]any{"sync": true, "bytes": len(payload)}})
			case adbCLSE:
				_, _ = conn.Write(adbMessage(adbCLSE, arg1, arg0, nil))
			case adbOKAY:
				// nothing to do
			default:
				log("payload", eventlog.Event{
					Details: map[string]any{"command": cmd, "bytes": len(payload)},
				})
			}
			_ = ctx
		}
	})
	return t
}

// readADBMessage reads one 24-byte header plus its payload.
func readADBMessage(conn net.Conn) (cmd, arg0, arg1 uint32, payload []byte, err error) {
	header := make([]byte, 24)
	if _, err = io.ReadFull(conn, header); err != nil {
		return
	}
	cmd = binary.LittleEndian.Uint32(header[0:4])
	arg0 = binary.LittleEndian.Uint32(header[4:8])
	arg1 = binary.LittleEndian.Uint32(header[8:12])
	length := binary.LittleEndian.Uint32(header[12:16])
	if length > 1<<20 {
		return cmd, arg0, arg1, nil, io.ErrUnexpectedEOF
	}
	if length > 0 {
		payload = make([]byte, length)
		if _, err = io.ReadFull(conn, payload); err != nil {
			return
		}
	}
	return cmd, arg0, arg1, payload, nil
}

func adbMessage(cmd, arg0, arg1 uint32, payload []byte) []byte {
	out := make([]byte, 24+len(payload))
	binary.LittleEndian.PutUint32(out[0:4], cmd)
	binary.LittleEndian.PutUint32(out[4:8], arg0)
	binary.LittleEndian.PutUint32(out[8:12], arg1)
	binary.LittleEndian.PutUint32(out[12:16], uint32(len(payload)))
	var sum uint32
	for _, b := range payload {
		sum += uint32(b)
	}
	binary.LittleEndian.PutUint32(out[16:20], sum)
	binary.LittleEndian.PutUint32(out[20:24], cmd^0xffffffff)
	copy(out[24:], payload)
	return out
}

func adbStreamKind(dest string) string {
	switch {
	case strings.HasPrefix(dest, "shell"):
		return "shell"
	case strings.HasPrefix(dest, "sync"):
		return "sync"
	case strings.HasPrefix(dest, "tcp:"), strings.HasPrefix(dest, "localabstract:"):
		return "forward"
	case strings.HasPrefix(dest, "framebuffer"):
		return "framebuffer"
	default:
		return "other"
	}
}

// adbFakeOutput answers the handful of commands droppers use to fingerprint
// a device before they try to install anything.
func adbFakeOutput(dest string) string {
	cmd := dest
	if i := strings.Index(cmd, ":"); i >= 0 {
		cmd = cmd[i+1:]
	}
	cmd = strings.TrimSpace(strings.TrimSuffix(cmd, "\x00"))
	switch {
	case cmd == "":
		return "shell@generic_x86:/ $ "
	case strings.HasPrefix(cmd, "getprop"):
		return "[ro.product.model]: [generic_x86]\n[ro.build.version.release]: [9]\n"
	case strings.HasPrefix(cmd, "id"):
		return "uid=0(root) gid=0(root) groups=0(root)\n"
	case strings.HasPrefix(cmd, "uname"):
		return "Linux localhost 4.14.112 #1 SMP PREEMPT armv8l\n"
	case strings.HasPrefix(cmd, "cat /proc/cpuinfo"):
		return "processor\t: 0\nmodel name\t: ARMv8 Processor rev 4 (v8l)\n"
	case strings.HasPrefix(cmd, "ls"):
		return "acct\nbin\ncache\nconfig\nd\ndata\ndefault.prop\ndev\netc\nsdcard\nsystem\nvendor\n"
	case strings.HasPrefix(cmd, "pm list packages"):
		return "package:com.android.settings\npackage:com.android.shell\n"
	default:
		return ""
	}
}
