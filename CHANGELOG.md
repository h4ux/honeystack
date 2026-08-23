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
