package honeypots

import (
	"math/rand"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
)

func defaultFakeAuth() *config.SshFakeAuth {
	return &config.SshFakeAuth{
		Mode:              "random",
		AcceptProbability: 0.15,
		AcceptedUsernames: []string{"root", "admin", "ubuntu", "user", "test", "oracle", "pi", "git", "default"},
	}
}

func fakeAuthOrDefault(fa *config.SshFakeAuth) *config.SshFakeAuth {
	if fa == nil {
		return defaultFakeAuth()
	}
	if fa.Mode == "" {
		cp := *fa
		cp.Mode = "random"
		if cp.AcceptProbability <= 0 {
			cp.AcceptProbability = 0.15
		}
		return &cp
	}
	return fa
}

func shouldAccept(fa *config.SshFakeAuth, username, password string) bool {
	fa = fakeAuthOrDefault(fa)
	for _, u := range fa.RejectAlwaysUsernames {
		if u == username {
			return false
		}
	}
	if len(fa.AcceptedPasswords) > 0 {
		for _, p := range fa.AcceptedPasswords {
			if p == password {
				return true
			}
		}
	}
	inList := len(fa.AcceptedUsernames) == 0
	for _, u := range fa.AcceptedUsernames {
		if u == username {
			inList = true
			break
		}
	}
	prob := fa.AcceptProbability
	if prob <= 0 {
		prob = 0.15
	}
	switch fa.Mode {
	case "always":
		return inList
	case "random":
		return inList && rand.Float64() < prob
	case "random-any":
		return rand.Float64() < prob
	case "first-attempt":
		return inList
	case "never":
		return false
	default:
		return inList && rand.Float64() < prob
	}
}
