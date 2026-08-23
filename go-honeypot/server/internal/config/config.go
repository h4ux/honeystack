package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Control struct {
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	AuthKeyFile    string   `json:"authKeyFile"`
	AllowedOrigins []string `json:"allowedOrigins"`
	TLSCertFile    string   `json:"tlsCertFile,omitempty"`
	TLSKeyFile     string   `json:"tlsKeyFile,omitempty"`
}

type Storage struct {
	LogFile     string `json:"logFile"`
	MaxLogRows  int    `json:"maxLogRows"`
	HostKeyFile string `json:"hostKeyFile"`

	// Resource limits. A public honeypot is scanned continuously, so every
	// one of these is a memory or disk ceiling, not a nicety.
	//
	// MaxSessions caps the session table (0 = 20000). MaxDetailBytes caps
	// each captured detail value and the whole details map per event
	// (0 = 2048/8192). MaxLogFileMB rotates events.ndjson (0 = 128, -1
	// never rotates). StatsCacheMs serves the aggregate from cache instead
	// of walking the ring per request (0 = 3000). StdoutEvents controls the
	// journal: "important" (default), "all", or "none".
	MaxSessions    int    `json:"maxSessions,omitempty"`
	MaxDetailBytes int    `json:"maxDetailBytes,omitempty"`
	MaxLogFileMB   int    `json:"maxLogFileMb,omitempty"`
	StatsCacheMs   int    `json:"statsCacheMs,omitempty"`
	StdoutEvents   string `json:"stdoutEvents,omitempty"`
}

// GeoIP controls country lookups for attacker IPs. Lookups go to a public
// HTTP service, so disabling this keeps every address on the box.
type GeoIP struct {
	Enabled         bool   `json:"enabled"`
	Provider        string `json:"provider,omitempty"` // ipwho.is | ip-api | ipinfo
	URL             string `json:"url,omitempty"`      // overrides provider; {ip} placeholder
	CacheFile       string `json:"cacheFile,omitempty"`
	TTLHours        int    `json:"ttlHours,omitempty"`
	TimeoutMs       int    `json:"timeoutMs,omitempty"`
	RateLimitPerMin int    `json:"rateLimitPerMin,omitempty"`
}

type SshFakeAuth struct {
	Mode                  string   `json:"mode"`
	AcceptProbability     float64  `json:"acceptProbability"`
	AcceptedUsernames     []string `json:"acceptedUsernames"`
	AcceptedPasswords     []string `json:"acceptedPasswords"`
	RejectAlwaysUsernames []string `json:"rejectAlwaysUsernames"`
}

type SshShell struct {
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	Motd     string `json:"motd"`
}

type Service struct {
	Enabled        bool         `json:"enabled"`
	Port           int          `json:"port"`
	Protocol       string       `json:"protocol,omitempty"` // tcp (default) or udp
	Kind           string       `json:"kind,omitempty"`     // built-in name or generic/echo
	Banner         string       `json:"banner,omitempty"`
	Hostname       string       `json:"hostname,omitempty"`
	FakeAuth       *SshFakeAuth `json:"fakeAuth,omitempty"`
	Shell          *SshShell    `json:"shell,omitempty"`
	ServerHeader   string       `json:"serverHeader,omitempty"`
	LoginPagePath  string       `json:"loginPagePath,omitempty"`
	ServerVersion  string       `json:"serverVersion,omitempty"`
	IdleTimeoutSec int          `json:"idleTimeoutSec,omitempty"`
	CaptureBytes   int          `json:"captureBytes,omitempty"`
}

type Config struct {
	Control  Control            `json:"control"`
	Storage  Storage            `json:"storage"`
	GeoIP    *GeoIP             `json:"geoip,omitempty"`
	Services map[string]Service `json:"services"`
}

var (
	mu         sync.RWMutex
	defaults   Config
	userPath   string
	current    Config
	loadedOnce bool
)

func Init(defaultPath, userConfigPath string) (Config, error) {
	mu.Lock()
	defer mu.Unlock()
	if err := readInto(defaultPath, &defaults); err != nil {
		return Config{}, fmt.Errorf("reading defaults: %w", err)
	}
	userPath = userConfigPath
	if _, err := os.Stat(userConfigPath); os.IsNotExist(err) {
		if err := writeJSON(userConfigPath, defaults); err != nil {
			return Config{}, err
		}
		current = defaults
	} else {
		var user Config
		if err := readInto(userConfigPath, &user); err != nil {
			return Config{}, fmt.Errorf("reading user config: %w", err)
		}
		current = merge(defaults, user)
	}
	loadedOnce = true
	return current, nil
}

func Get() Config {
	mu.RLock()
	defer mu.RUnlock()
	return current
}

func Set(cfg Config) error {
	mu.Lock()
	defer mu.Unlock()
	if !loadedOnce {
		return fmt.Errorf("config not initialised")
	}
	if err := writeJSON(userPath, cfg); err != nil {
		return err
	}
	current = cfg
	return nil
}

func Path() string { return userPath }

func readInto(path string, out *Config) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func writeJSON(path string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// Geo returns the geoip block with defaults filled in, so callers never
// have to nil-check it.
func (c Config) Geo() GeoIP {
	if c.GeoIP == nil {
		return GeoIP{Enabled: false}
	}
	return *c.GeoIP
}

func merge(base, override Config) Config {
	out := base
	if override.Control.Host != "" {
		out.Control.Host = override.Control.Host
	}
	if override.Control.Port != 0 {
		out.Control.Port = override.Control.Port
	}
	if override.Control.AuthKeyFile != "" {
		out.Control.AuthKeyFile = override.Control.AuthKeyFile
	}
	if len(override.Control.AllowedOrigins) > 0 {
		out.Control.AllowedOrigins = override.Control.AllowedOrigins
	}
	if override.Storage.LogFile != "" {
		out.Storage.LogFile = override.Storage.LogFile
	}
	if override.Storage.MaxLogRows != 0 {
		out.Storage.MaxLogRows = override.Storage.MaxLogRows
	}
	if override.Storage.HostKeyFile != "" {
		out.Storage.HostKeyFile = override.Storage.HostKeyFile
	}
	if override.Storage.MaxSessions != 0 {
		out.Storage.MaxSessions = override.Storage.MaxSessions
	}
	if override.Storage.MaxDetailBytes != 0 {
		out.Storage.MaxDetailBytes = override.Storage.MaxDetailBytes
	}
	if override.Storage.MaxLogFileMB != 0 {
		out.Storage.MaxLogFileMB = override.Storage.MaxLogFileMB
	}
	if override.Storage.StatsCacheMs != 0 {
		out.Storage.StatsCacheMs = override.Storage.StatsCacheMs
	}
	if override.Storage.StdoutEvents != "" {
		out.Storage.StdoutEvents = override.Storage.StdoutEvents
	}
	if override.GeoIP != nil {
		out.GeoIP = override.GeoIP
	}
	if override.Services != nil {
		if out.Services == nil {
			out.Services = map[string]Service{}
		}
		for k, v := range override.Services {
			out.Services[k] = v
		}
	}
	return out
}
