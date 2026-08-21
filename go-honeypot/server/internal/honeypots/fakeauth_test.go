package honeypots

import (
	"testing"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
)

func TestShouldAcceptAlways(t *testing.T) {
	fa := &config.SshFakeAuth{Mode: "always", AcceptedUsernames: []string{"root"}}
	if !shouldAccept(fa, "root", "x") {
		t.Fatal("expected accept")
	}
	if shouldAccept(fa, "other", "x") {
		t.Fatal("expected reject unknown user")
	}
	never := &config.SshFakeAuth{Mode: "never", AcceptedUsernames: []string{"root"}}
	if shouldAccept(never, "root", "x") {
		t.Fatal("never should reject")
	}
}
