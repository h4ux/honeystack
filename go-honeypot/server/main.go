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
	"strings"
	"syscall"
	"time"

	"github.com/example/honeypot/internal/config"
	"github.com/example/honeypot/internal/controlapi"
	"github.com/example/honeypot/internal/eventlog"
	"github.com/example/honeypot/internal/honeypots"
	"github.com/example/honeypot/internal/manager"
)

var (
	version = "dev"
	commit  = "none"

	flagDefaults = flag.String("defaults", "config.default.json", "path to shipped defaults")
	flagConfig   = flag.String("config", "config.json", "path to writable user config")
)

func main() {
	flag.Parse()
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

	store, err := eventlog.New(cfg.Storage.LogFile, cfg.Storage.MaxLogRows)
	if err != nil {
		log.Fatalf("eventlog init: %v", err)
	}
	defer store.Close()

	// Mirror every event to stdout for operators.
	store.Subscribe(func(e eventlog.Event) {
		fmt.Println(formatEvent(e))
	})

	mgr := manager.New(store)
	registerHoneypots(mgr, cfg, store)
	mgr.Sync(cfg)
	defer mgr.StopAll()

	authKey, err := controlapi.GenerateAuthKey(cfg.Control.AuthKeyFile)
	if err != nil {
		log.Fatalf("auth key: %v", err)
	}
	printBanner(cfg, authKey)

	api := controlapi.New(store, mgr, func(newCfg config.Config) { mgr.Sync(newCfg) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := api.Start(ctx, cfg.Control, authKey); err != nil {
		log.Fatalf("control api: %v", err)
	}

	store.Log(eventlog.Event{Service: "system", Type: "startup", Details: map[string]any{"pid": os.Getpid()}})

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	sig := <-stop
	log.Printf("[system] received %s, shutting down…", sig)

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

func printBanner(cfg config.Config, key string) {
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
	fmt.Printf("  control endpoint : ws://%s:%d/api\n", host, cfg.Control.Port)
	fmt.Printf("  auth key         : %s\n", key)
	fmt.Printf("  key file         : %s\n", cfg.Control.AuthKeyFile)
	fmt.Println("  Connect the local webapp to this endpoint with the auth key above.")
	fmt.Println(line)
}
