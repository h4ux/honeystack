// honeypot server: a headless honeypot daemon controlled over a
// WebSocket API. On startup it prints an auth key which the local
// webapp uses to connect over the network.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/h4ux/honeystack/go-honeypot/server/internal/config"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/controlapi"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/eventlog"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/geoip"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/honeypots"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/manager"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/pubaddr"
	"github.com/h4ux/honeystack/go-honeypot/server/internal/sdnotify"
)

var (
	version = "dev"
	commit  = "none"
	// repo is where update checks look for a newer build. Overridable at
	// build time: -X main.repo=owner/name
	repo = "h4ux/honeystack"

	flagDefaults = flag.String("defaults", "config.default.json", "path to shipped defaults")
	flagConfig   = flag.String("config", "config.json", "path to writable user config")
	flagVersion  = flag.Bool("version", false, "print version and exit")
)

func main() {
	flag.Parse()
	if *flagVersion {
		// scripts/update-server.sh parses this line: keep "commit <sha>"
		// and "repo=<owner/name>" in it.
		fmt.Printf("honeypot %s (commit %s, %s, %s/%s, repo=%s)\n",
			version, commit, runtime.Version(), runtime.GOOS, runtime.GOARCH, repo)
		return
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if abs, err := filepath.Abs(*flagDefaults); err == nil {
		*flagDefaults = abs
	}
	if abs, err := filepath.Abs(*flagConfig); err == nil {
		*flagConfig = abs
	}

	cfg, err := config.Init(*flagDefaults, *flagConfig)
	if err != nil {
		log.Fatalf("config init: %v", err)
	}

	store, err := eventlog.NewWithOptions(cfg.Storage.LogFile, eventlog.Options{
		MaxRows:        cfg.Storage.MaxLogRows,
		MaxSessions:    cfg.Storage.MaxSessions,
		MaxDetailBytes: cfg.Storage.MaxDetailBytes,
		MaxLogFileMB:   cfg.Storage.MaxLogFileMB,
		StatsCacheMs:   cfg.Storage.StatsCacheMs,
	})
	if err != nil {
		log.Fatalf("eventlog init: %v", err)
	}
	defer store.Close()

	// Country lookups are optional and never block a honeypot handler: the
	// resolver answers from cache and fills misses on a background worker.
	geo := geoip.New(cfg.Geo())
	defer geo.Close()
	store.SetGeo(geo)

	// Public address tracking: keeps a hostname pointed at this host when
	// its IP is not static, and records every change. Created before the
	// banner so the banner can print the URL, started after the API is up.
	tracker := pubaddr.New(cfg.Dyn(), store)
	defer tracker.Close()

	// Mirror events to stdout for operators. On a scanned host this goes to
	// the systemd journal, so "all" is a real CPU and disk cost — the
	// default keeps the lines that matter and drops connection noise.
	switch strings.ToLower(cfg.Storage.StdoutEvents) {
	case "none", "off", "false":
		log.Printf("[system] event mirroring to stdout is off (storage.stdoutEvents)")
	case "all":
		store.Subscribe(func(e eventlog.Event) {
			fmt.Println(formatEvent(e))
		})
	default: // "important"
		store.Subscribe(func(e eventlog.Event) {
			if interestingEvent(e) {
				fmt.Println(formatEvent(e))
			}
		})
	}

	mgr := manager.New(store)
	registerHoneypots(mgr, cfg, store)
	mgr.SetFallback(func(name string, c config.Service, s *eventlog.Store) (manager.Service, error) {
		if strings.EqualFold(c.Protocol, "udp") {
			return honeypots.NewUDP(name, c, s), nil
		}
		return honeypots.NewGeneric(name, c, s), nil
	})
	mgr.Sync(cfg)
	defer mgr.StopAll()

	authKey, err := controlapi.GenerateAuthKey(cfg.Control.AuthKeyFile)
	if err != nil {
		log.Fatalf("auth key: %v", err)
	}
	printBanner(cfg, authKey, tracker)

	api := controlapi.New(store, mgr, func(newCfg config.Config) { mgr.Sync(newCfg) })
	api.SetGeo(geo)
	api.SetPublicAddr(tracker)
	binPath, _ := os.Executable()
	api.SetBuildInfo(controlapi.BuildInfo{
		Version:   version,
		Commit:    commit,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		StartedAt: time.Now().UnixMilli(),
		Repo:      repo,
		Binary:    binPath,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := api.Start(ctx, cfg.Control, authKey); err != nil {
		log.Fatalf("control api: %v", err)
	}

	store.Log(eventlog.Event{Service: "system", Type: "startup", Details: map[string]any{"pid": os.Getpid()}})

	// systemd shows this under the unit description, so `systemctl status`
	// answers "what is the URL again?" without digging through the journal.
	statusLine := func() string {
		st := tracker.Status()
		parts := []string{}
		if st.URL != "" {
			parts = append(parts, st.URL)
		}
		if st.IP != "" {
			parts = append(parts, st.IP)
		} else if st.Enabled {
			parts = append(parts, "public IP pending")
		}
		parts = append(parts, fmt.Sprintf("control :%d", cfg.Control.Port))
		parts = append(parts, fmt.Sprintf("%d listeners", len(mgr.List())))
		return strings.Join(parts, " · ")
	}
	tracker.SetOnChange(func(st pubaddr.Status) {
		sdnotify.Status(statusLine())
		if st.URL != "" {
			log.Printf("[pubaddr] reachable at %s (%s), updated %s",
				st.URL, st.IP, st.UpdateStatus)
		}
	})
	sdnotify.Ready(statusLine())
	tracker.Start(ctx)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	sig := <-stop
	log.Printf("[system] received %s, shutting down…", sig)
	sdnotify.Stopping("shutting down")

	shutCtx, cancelShut := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShut()
	_ = api.Stop(shutCtx)
}

func registerHoneypots(m *manager.Manager, cfg config.Config, store *eventlog.Store) {
	hostKeyPath := cfg.Storage.HostKeyFile
	if hostKeyPath == "" {
		hostKeyPath = "data/ssh_host_ed25519_key"
	}
	m.Register("ssh", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewSSH(c, s, hostKeyPath)
	})
	m.Register("telnet", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewTelnet(c, s), nil
	})
	m.Register("ftp", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewFTP(c, s), nil
	})
	m.Register("http", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewHTTP(c, s), nil
	})
	m.Register("rdp", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewRDP(c, s), nil
	})
	m.Register("mysql", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewMySQL(c, s), nil
	})
	m.Register("vnc", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewVNC(c, s), nil
	})
	m.Register("smb", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewSMB(c, s), nil
	})
	m.Register("redis", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewRedis(c, s), nil
	})
	m.Register("postgres", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewPostgres(c, s), nil
	})
	m.Register("clickhouse", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewClickHouseHTTP(c, s), nil
	})
	m.Register("clickhouse-native", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewClickHouseNative(c, s), nil
	})
	m.Register("mssql", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewMSSQL(c, s), nil
	})
	m.Register("mongodb", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewMongoDB(c, s), nil
	})
	m.Register("elasticsearch", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewElasticsearch(c, s), nil
	})
	m.Register("docker", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewDocker(c, s), nil
	})
	m.Register("mqtt", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewMQTT(c, s), nil
	})

	// Mail
	m.Register("smtp", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewSMTP(c, s), nil
	})
	m.Register("smtp-submission", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewSMTP(c, s), nil
	})
	m.Register("imap", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewIMAP(c, s), nil
	})
	m.Register("pop3", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewPOP3(c, s), nil
	})

	// Caches, directories, file sync, device debugging
	m.Register("memcached", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewMemcached(c, s), nil
	})
	m.Register("ldap", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewLDAP(c, s), nil
	})
	m.Register("rsync", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewRsync(c, s), nil
	})
	m.Register("adb", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewADB(c, s), nil
	})

	// Open proxies — what proxy scanners are hunting for
	m.Register("squid", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewSquid(c, s), nil
	})
	m.Register("http-proxy", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewHTTPProxy(c, s), nil
	})
	m.Register("socks", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewSOCKS(c, s), nil
	})

	// VPN endpoints
	m.Register("openvpn", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewOpenVPN("openvpn", c, s), nil
	})
	m.Register("openvpn-tcp", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewOpenVPNTCP(c, s), nil
	})
	m.Register("ipsec-ike", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewIKE("ipsec-ike", c, s), nil
	})
	m.Register("ipsec-natt", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewIKE("ipsec-natt", c, s), nil
	})
	m.Register("wireguard", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewWireGuard("wireguard", c, s), nil
	})
	m.Register("l2tp", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewL2TP("l2tp", c, s), nil
	})
	m.Register("pptp", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewPPTP(c, s), nil
	})

	// UDP infrastructure (reflection/amplification targets)
	m.Register("dns", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewDNS("dns", c, s), nil
	})
	m.Register("snmp", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewSNMP("snmp", c, s), nil
	})
	m.Register("ntp", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewNTP("ntp", c, s), nil
	})
	m.Register("tftp", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewTFTP("tftp", c, s), nil
	})
	m.Register("sip", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewSIP("sip", c, s), nil
	})
	m.Register("sip-tcp", func(c config.Service, s *eventlog.Store) (manager.Service, error) {
		return honeypots.NewSIPTCP(c, s), nil
	})
}

// interestingEvent picks the events worth a journal line: credentials,
// commands, and anything indicating abuse. Plain connections and payload
// dumps are left to the dashboard and events.ndjson.
func interestingEvent(e eventlog.Event) bool {
	switch e.Type {
	case "auth_success", "authenticated", "login_attempt", "auth_attempt",
		"command", "exec", "mail_relay", "relay_attempt", "proxy_connect",
		"proxy_request", "upload_attempt", "amplification_attempt",
		"service_error", "server_error", "handler_error", "startup", "shutdown":
		return true
	}
	return false
}

func formatEvent(e eventlog.Event) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] [%s] [%s]", time.UnixMilli(e.TS).UTC().Format(time.RFC3339Nano), e.Service, e.Type)
	if e.RemoteIP != "" {
		fmt.Fprintf(&b, " %s:%d", e.RemoteIP, e.RemotePort)
	}
	if e.Username != "" {
		fmt.Fprintf(&b, " user=%q", e.Username)
	}
	if e.Password != "" {
		fmt.Fprintf(&b, " pass=%q", e.Password)
	}
	if e.Command != "" {
		fmt.Fprintf(&b, " cmd=%q", e.Command)
	}
	return b.String()
}

func printBanner(cfg config.Config, key string, addr *pubaddr.Tracker) {
	host := cfg.Control.Host
	if host == "" || host == "0.0.0.0" {
		host = "<your-server-ip>"
	}
	line := strings.Repeat("=", 68)
	fmt.Println(line)
	fmt.Println("  honeypot daemon started")
	if version != "" && version != "dev" {
		fmt.Printf("  version          : %s (%s)\n", version, commit)
	} else if commit != "" && commit != "none" {
		fmt.Printf("  version          : %s\n", commit)
	}
	geoCfg := cfg.Geo()
	if geoCfg.Enabled {
		provider := geoCfg.Provider
		if provider == "" {
			provider = "ipwho.is"
		}
		fmt.Printf("  geoip            : on (%s) — attacker IPs are sent to this provider\n", provider)
	} else {
		fmt.Println("  geoip            : off")
	}
	if url := addr.URL(); url != "" {
		fmt.Printf("  public address   : %s   (dyndns: %s, refreshed every %dm)\n",
			url, providerName(cfg.Dyn()), intervalOf(cfg.Dyn()))
	} else if cfg.Dyn().Enabled {
		fmt.Println("  public address   : dyndns enabled but no hostname yet — see data/dyndns.json")
	}
	fmt.Printf("  control endpoint : ws://%s:%d/api\n", host, cfg.Control.Port)
	fmt.Printf("  auth key         : %s\n", key)
	fmt.Printf("  key file         : %s\n", cfg.Control.AuthKeyFile)
	fmt.Println("  Connect the local webapp to this endpoint with the auth key above.")
	fmt.Println(line)
}

func providerName(d config.DynDNS) string {
	if d.Provider != "" {
		return d.Provider
	}
	if d.UpdateURL != "" {
		return "custom"
	}
	return "xyz.frl"
}

func intervalOf(d config.DynDNS) int {
	if d.IntervalMinutes > 0 {
		return d.IntervalMinutes
	}
	return 5
}
