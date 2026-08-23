// Package sdnotify speaks the small part of the systemd notification
// protocol we need: setting the one-line status that `systemctl status`
// prints under the unit description.
//
// It is a no-op when NOTIFY_SOCKET is unset (running by hand, in a
// container, or on a non-systemd host), so callers never have to check.
// The unit needs NotifyAccess=main for systemd to accept these.
package sdnotify

import (
	"net"
	"os"
	"strings"
	"sync"
)

var (
	mu   sync.Mutex
	last string
)

// Available reports whether systemd is listening.
func Available() bool { return os.Getenv("NOTIFY_SOCKET") != "" }

// Status sets the unit's status line, e.g.
//
//	Status: "https://abc.xyz.frl → 203.0.113.7 · 41 listeners"
//
// Repeated identical values are dropped so a five-minute refresh does not
// wake systemd for nothing.
func Status(text string) {
	if text == "" {
		return
	}
	mu.Lock()
	if text == last {
		mu.Unlock()
		return
	}
	last = text
	mu.Unlock()
	send("STATUS=" + oneLine(text))
}

// Ready tells systemd the daemon finished starting, with an initial status.
// Harmless for Type=simple units.
func Ready(text string) {
	msg := "READY=1"
	if text != "" {
		msg += "\nSTATUS=" + oneLine(text)
		mu.Lock()
		last = text
		mu.Unlock()
	}
	send(msg)
}

// Stopping marks a clean shutdown in progress.
func Stopping(text string) {
	msg := "STOPPING=1"
	if text != "" {
		msg += "\nSTATUS=" + oneLine(text)
	}
	send(msg)
}

func send(msg string) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	// A leading '@' means an abstract socket on Linux.
	name := addr
	if strings.HasPrefix(addr, "@") {
		name = "\x00" + addr[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte(msg))
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
