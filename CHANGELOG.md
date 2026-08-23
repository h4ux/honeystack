# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). There
are no versioned releases yet: `main` is published continuously as the
`nightly` release, so entries are grouped by date.

## [Unreleased]

### Security

- Bumped `golang.org/x/crypto` from 0.31.0 to 0.52.0, clearing all 16 open
  Dependabot alerts (7 critical, 3 high, 6 moderate) against the SSH
  stack. This raises the Go floor to **1.25** (CI builds on 1.26.7).
- Added [`SECURITY.md`](./SECURITY.md) with a private reporting channel
  and an explicit scope — a honeypot accepting fake logins is not a
  vulnerability; an emulator that forwards traffic or amplifies a UDP
  reply is.
- `.github/dependabot.yml` now watches Go modules (with the vendor tree),
  npm and GitHub Actions weekly, and CI runs `govulncheck` on every PR.

### Added

- **Beacon: the dashboard finds the host after its IP changes.** The
  daemon publishes a signed `{ip, controlPort, updatedAt}` document to a URL
  that never changes (ntfy.sh by default — no account, and it serves
  `access-control-allow-origin: *` so the static dashboard can read it).
  The dashboard learns the locator on first connect, and when the socket
  drops it reads the beacon, verifies the HMAC against the key held in the
  URL fragment, and reconnects at the new address. A `custom` backend
  covers any endpoint that accepts a body and serves it back with CORS.
- **Cloudflare DNS provider** for anyone who owns a domain: discovers zone
  and record by name, creates the A record when missing, then PATCHes it
  (TTL 60, proxy off) with a scoped API token.
- **Public address tracking and dynamic DNS.** The daemon polls its own
  public IP every `dyndns.intervalMinutes` (default 5), records every
  change to `data/ip-history.json`, logs it as a `public_ip_changed`
  event, and pushes the address to a DynDNS-style provider (`xyz.frl` by
  default: `sslip.io`, which needs no account, no credential and no update
  request because the address is encoded in the name; plus `xyz.frl`,
  DuckDNS, No-IP or any `updateUrl` template). The URL shows
  up in the startup banner, in `systemctl status` via `sd_notify`, in the
  dashboard's new **Stats → Public address** panel with the full change
  log, and at `GET /v1/pubaddr`. `scripts/deploy-remote.sh` can mint a
  public name during install (step 3 of 5): `sslip.io` by default with
  nothing to store, or an anonymous `xyz.frl` name whose credential goes
  to `data/dyndns.json` (0600). Caveat: xyz.frl accepted
  updates (HTTP 202) but its hostnames did not resolve when this was
  written — tracking and the change log do not depend on that.

### Documentation

- New [`docs/`](./docs) folder: [architecture.md](./docs/architecture.md)
  (package layout and dependency direction, startup sequence, the
  probe→event hot path, listener lifecycle, goroutine and lock map, the
  control API, and the design constraints) and
  [storage.md](./docs/storage.md) (every file written, the pattern used for
  each, the NDJSON format with `jq` recipes, in-memory limits, what boot
  restores, backup/shrink/ship recipes, permissions, and the full list of
  attacker-influenced bounds).

### Fixed

- `config.json` is now replaced atomically (temp + rename). The dashboard
  rewrites it on every config change, so a crash mid-write could leave a
  truncated file the daemon could not parse on the next boot.


- **Unbounded memory growth.** Nothing ever removed rows from the session
  table, and UDP opened a session *per datagram* — an SNMP/NTP sweep grew
  it forever (measured: 252 MB per million sessions). Sessions are now
  capped (`storage.maxSessions`, default 20,000, oldest closed dropped
  first) and UDP groups a source into one session per 2-minute window.
- **Event ring memory.** A full ring of HTTP events with headers and
  bodies measured 380 MB. Captured `details` are now capped per event
  (`storage.maxDetailBytes`, default 2048), HTTP body capture dropped from
  256 KB/64 KB to 16 KB, and the default `maxLogRows` from 200,000 to
  25,000. A 54,000-event flood now settles at 84 MB live heap.
- **CPU spent recomputing stats.** `Stats()` walks the whole ring (193 ms
  at 200k events) and every dashboard asked for it every 2 seconds. It is
  now served from a short cache (`storage.statsCacheMs`, default 3s):
  0.4 ms per request, 0.1% of a core at idle instead of ~10%.
- **`events.ndjson` grew without limit** and was read in full at boot. It
  now rotates at `storage.maxLogFileMb` (default 128 MB, one generation
  kept), and startup replays only the tail it can actually hold.
- **Every event was mirrored to the journal.** `storage.stdoutEvents`
  defaults to `important` (credentials, commands, relay/proxy attempts,
  amplification, errors): 807 journal lines for 54,000 events instead of
  54,000.
- `Store.Close()` panicked if called twice.

### Added

- The `/v1/version` payload (and the dashboard's build panel) now report
  live heap, reserved memory, goroutines, CPU count, `GOMEMLIMIT` and the
  retention caps, so an operator can see the daemon's footprint without
  shelling into the box.
- `deploy-remote.sh` writes `GOMEMLIMIT`, `MemoryHigh`, `MemoryMax` and
  `CPUWeight` into the systemd unit (`--memory MB` to change the budget,
  default 192 MiB).


- **24 new honeypot services** (41 listeners total):
  - Mail: SMTP (25), SMTP submission (587), IMAP (143), POP3 (110) —
    `AUTH LOGIN`/`PLAIN` credential capture and open-relay probes.
  - Open proxies: Squid-style HTTP proxy (3128), HTTP proxy (8080),
    SOCKS4/4a/5 (1080) — `CONNECT` targets, proxy credentials, and an
    `intent` label for the abuse pattern behind the port.
  - VPN endpoints: OpenVPN (UDP + TCP), IPsec/IKE (500, 4500), WireGuard
    (51820), L2TP (1701), PPTP (1723).
  - UDP infrastructure: SIP (UDP + TCP), DNS (off by default), SNMP, NTP,
    TFTP — with amplification attempts logged and never answered.
  - Also Memcached (11211), LDAP (389), rsync (873) and ADB (5555).
  None of them execute, forward, relay or amplify anything.
- **GeoIP**: every event and session carries country, ISO code and network
  operator, resolved on a background worker and cached on disk
  (`data/geoip-cache.json`). New `geoip` config block, `/v1/geo` endpoint
  and `geo_lookup` action. Private addresses are never sent anywhere, and
  the whole feature switches off with `geoip.enabled: false`.
- **Version awareness and updates**: the daemon reports its build
  (`honeypot --version`, `GET /v1/version`, and the `hello` payload); the
  dashboard compares it with the latest published release and shows an
  **⬆ update available** chip with copy-paste instructions.
  [`scripts/update-server.sh`](./go-honeypot/scripts/update-server.sh)
  updates in place with checksum verification, backups and automatic
  rollback (`--check`, `--force`, `--rollback`, `--yes`).
- **Long payloads no longer break the layout**: multi-KB attacker
  one-liners are clamped to one line in tables (two in the live feed) with
  a size badge and a `view` pill that opens the full text in a dialog
  (wrap toggle, copy button, and the event's service/type/IP/country/time).
  Ranking tables use `table-layout: fixed`, so no single token can widen a
  column past the viewport. Exports keep the full text.
- **Run-scoped timing in Stats**: a live-ticking "uptime this run" tile,
  a "first hit after start" tile (how long the host sat untouched, which
  listener was hit, and how many hits the run has seen), and two new
  per-service columns — events this run, and time from daemon start to
  that listener's first hit (`not yet` while it is untouched). The
  daemon's own startup events do not count as a hit. Exposed as
  `startedAt`, `uptimeMs`, `eventsSinceStart`, `trafficSinceStart`,
  `timeToFirstEventMs` and per-service `timeToFirstMs`.
- **Session filters**: filter by free text (id, IP, username, country,
  operator), service, country, state, source IP, username and minimum
  command count, sorted by recency, command count or duration — all
  evaluated on the daemon.
- **Service icons**: a drawn glyph per protocol family in
  `webapp/icons.js`, used in the feed, service cards, session list and
  stats tables. No vendor logos ship with the dashboard.
- Open-source scaffolding: `LICENSE` (MIT), `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `SUPPORT.md`, this changelog, issue forms, a PR
  template, `CODEOWNERS`, `.editorconfig`, and a `ci` workflow (gofmt,
  vet, race tests, vendor-in-sync, govulncheck, dashboard and script
  syntax, service/icon consistency).

### Changed

- The deploy script opens UDP decoy ports as UDP instead of silently as
  TCP when you keep the firewall enabled.
- `setup-ubuntu.sh` no longer pins `GOTOOLCHAIN=local`, since the module
  now needs a newer Go than Ubuntu ships.

## 2026-08-21

### Added

- [`scripts/deploy-remote.sh`](./go-honeypot/scripts/deploy-remote.sh):
  step-by-step server deployment that asks before each change — picks the
  release binary for the host's OS/CPU (SHA-256 verified), moves the real
  sshd to port 1980 with an `sshd -t` fail-safe, installs and starts the
  systemd service, and disables the host firewall (or opens just the
  ports it needs).
- Dashboard stats rebuilt: 11 KPI tiles, eight colour-coded canvas charts
  (24 h activity, per-service donut, event types, noisiest IPs, targeted
  ports, source countries, 14-day volume, weekday×hour heatmap), a
  per-service breakdown table and rankings for credentials, usernames,
  passwords, commands, HTTP paths and client fingerprints. Charts are
  repainted light-themed at print resolution for the PDF report.
- A counter strip on the Live tab, and per-listener traffic on the
  Services tab.

### Fixed

- `Stats.hourly` was ranked by count, so it could not be plotted as a time
  series; it is now chronological.
- Credential counters double-counted SSH successes and reported every
  attempt as "rejected". Attempts are now counted per service according to
  how each listener logs authentication.
- The nightly release never published: `gh release create --prerelease
  --latest` is rejected by GitHub, so every build since the first push had
  failed at that step.
