# Honeystack

[![ci](https://github.com/h4ux/honeystack/actions/workflows/ci.yml/badge.svg)](https://github.com/h4ux/honeystack/actions/workflows/ci.yml)
[![go-honeypot build](https://github.com/h4ux/honeystack/actions/workflows/go-honeypot.yml/badge.svg)](https://github.com/h4ux/honeystack/actions/workflows/go-honeypot.yml)
[![nightly release](https://img.shields.io/github/v/release/h4ux/honeystack?include_prereleases&label=nightly)](https://github.com/h4ux/honeystack/releases/tag/nightly)
[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go&logoColor=white)](go-honeypot/server/go.mod)
[![licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)


Two implementations of the same multi-service honeypot:

| | **Node.js** (this directory) | **Go** (`go-honeypot/`) |
|---|---|---|
| Runtime | Node 18+ | Single static binary |
| Dashboard | Built into the process (`:8080`) | Separate webapp; talks to the binary over WebSocket |
| Storage | SQLite (`data/honeypot.db`) | In-memory ring + `events.ndjson` |
| Auth for the UI | HTTP basic (`admin` / `changeme`) | Per-run auth key printed at startup |
| Deploy | `setup-ubuntu.sh` | `go-honeypot/scripts/deploy-remote.sh` (curl-able, step-by-step) or `go-honeypot/setup-ubuntu.sh` |
| Update | manual `git pull` | `go-honeypot/scripts/update-server.sh` (checksum-verified, auto-rollback) |
| Services | 10 | 41, incl. mail, proxies, VPN and UDP infrastructure |
| GeoIP | — | country/ASN per source IP, cached on disk |

Both emulate **SSH, Telnet, FTP, HTTP, RDP, MySQL, VNC, SMB, Redis,
and PostgreSQL**. The Go edition runs **41 listeners**, adding
**ClickHouse (HTTP + native), MSSQL, MongoDB, Elasticsearch, Docker
Engine API, MQTT, Memcached, LDAP, rsync, ADB**, mail (**SMTP,
submission, IMAP, POP3**), open proxies (**Squid-style HTTP proxy, HTTP
proxy, SOCKS4/5**), VPN endpoints (**OpenVPN, IPsec/IKE, WireGuard,
L2TP, PPTP**) and UDP infrastructure (**SIP, DNS, SNMP, NTP, TFTP**).
It also resolves attacker IPs to countries. They log connections and
credential attempts and capture commands typed in a fake SSH shell. Pick
one; do not run both on the same ports.

---

# Node.js version

A honeypot suite with a live web dashboard. Emulates a handful of common
services so you can watch scanners and brute-force bots hit them in real
time, log every credential attempt, and capture the commands attackers
run inside a fake SSH shell.

## Features

- **Multiple honeypot services** — SSH, Telnet, FTP, HTTP, RDP, MySQL,
  VNC, SMB, Redis, PostgreSQL. Enable/disable each per port.
- **Fake SSH shell** — configurable random / always / never accept
  authentication. Once "logged in", attackers see a plausible Ubuntu
  prompt with `ls`, `cat`, `uname`, `whoami`, etc., and every command
  they type is logged and streamed to the dashboard.
- **Live dashboard** — Express + Socket.IO. Filter by service/type/IP,
  browse SSH session transcripts, see per-service stats, top attacker
  IPs, top credentials, top commands.
- **Persistent storage** — SQLite (via `better-sqlite3`). Everything is
  logged to `data/honeypot.db`.
- **Config-driven** — edit `config.json` (or use the dashboard's config
  editor) and services are restarted automatically.
- **Ubuntu deployment script** — moves the real sshd to a safe port,
  opens the firewall, installs Node, installs a systemd service.

## Quick start (locally, on any OS)

```bash
npm install
npm start
```

Then open <http://localhost:8080> (login: `admin` / `changeme`).

Note: binding to privileged ports (<1024) requires root or the
`CAP_NET_BIND_SERVICE` capability. If you just want to poke at it
locally, set the ports in `config.json` to unprivileged ones (e.g.
`2222` for SSH, `2323` for Telnet, `8081` for HTTP).

## Ubuntu deployment (Node)

See [INSTRUCTIONS.md](./INSTRUCTIONS.md) and use `setup-ubuntu.sh`.
The script will:

1. Move real sshd from port `22` to `1980` (with backup + fail-safe).
2. Install Node.js 20.
3. Install dependencies.
4. Open the firewall (`ufw`) for all honeypot ports + real sshd + dashboard.
5. Install a `honeypot.service` systemd unit.

Run it as root:

```bash
sudo bash setup-ubuntu.sh
```

## Configuration (Node)

- `config.default.json` — shipped defaults; do not edit.
- `config.json` — created on first run, edit freely (or use the
  dashboard). Applied instantly on save.

### SSH fake-auth modes

```jsonc
"fakeAuth": {
  "mode": "random",             // always | random | random-any | first-attempt | never
  "acceptProbability": 0.15,     // used by 'random' modes
  "acceptedUsernames": ["root", "admin", "ubuntu"],
  "acceptedPasswords": [],       // optional password whitelist
  "rejectAlwaysUsernames": []
}
```

- `always` — always accept known usernames.
- `random` — accept known usernames with probability `acceptProbability`.
- `random-any` — accept any username with probability `acceptProbability`.
- `first-attempt` — accept the first login attempt of a known username.
- `never` — always reject (still logs everything).

## Project layout (Node)

```
src/
  index.js              entry point
  config.js             load / save JSON config
  db.js                 sqlite schema + queries
  logger.js             central event bus + persistence
  manager.js            starts/stops honeypot services from config
  dashboard/server.js   express + socket.io
  honeypots/
    base.js             TCP honeypot base class
    ssh.js              SSH honeypot (fake shell)
    ssh_shell.js        fake shell command emulator
    telnet.js
    ftp.js
    http.js
    rdp.js
    mysql.js
    vnc.js
    smb.js
    redis.js
    postgres.js
public/                 dashboard UI (no build step)
setup-ubuntu.sh         Ubuntu deployment script
INSTRUCTIONS.md         deployment / operations guide
config.default.json     shipped defaults
```

---

# Go version (`go-honeypot/`)

A headless Go rewrite of the same honeypot. The **daemon** only opens
the decoy ports and a WebSocket control API. The **dashboard** is a
separate static webapp you run on your laptop (or anywhere) and point
at the daemon with host, port, and a per-run auth key.

Full write-up: [go-honeypot/README.md](./go-honeypot/README.md)  
Ubuntu ops: [go-honeypot/INSTRUCTIONS.md](./go-honeypot/INSTRUCTIONS.md)

## How it is different from Node

- No Node runtime on the server — one static binary.
- 41 listeners instead of 10: mail (SMTP/submission/IMAP/POP3), open
  proxies (Squid-style, HTTP, SOCKS4/5), VPN endpoints (OpenVPN,
  IPsec/IKE, WireGuard, L2TP, PPTP), UDP infrastructure (SIP, DNS, SNMP,
  NTP, TFTP), plus Memcached, LDAP, rsync and ADB.
- Source IPs are resolved to **country / city / ASN**, cached on disk, and
  shown as a flag next to every address (switch off with
  `geoip.enabled: false`).
- Reports its own build over the API, so the dashboard can tell you when a
  newer release is published and hand you the update command.
- Dashboard is **not** served by the honeypot. You connect remotely.
- Every start generates a new 64-char hex **auth key** (also written to
  `go-honeypot/server/data/auth.key`). That key is the only thing that
  can talk to the control API.
- Events live in memory (last 200k) plus `data/events.ndjson` — no CGO,
  no SQLite.

On startup the daemon prints:

```
====================================================================
  honeypot daemon started
  control endpoint : ws://<your-server-ip>:9090/api
  auth key         : 8f4a...9c0e
  key file         : data/auth.key
  Connect the local webapp to this endpoint with the auth key above.
====================================================================
```

## Quick start (Go, locally)

You need **Go 1.25+** and **Node** only for the tiny local webapp server
(or open `index.html` directly).

Terminal 1 — daemon:

```bash
cd go-honeypot/server
# first run copies config.default.json → config.json
go run . --config config.json
```

If you cannot bind privileged ports, edit `config.json` first and move
SSH to `2222`, HTTP to `8081`, etc. The control API defaults to
`127.0.0.1:9090` unless you change `control.host` / `control.port`.

Copy the **auth key** from the banner.

Terminal 2 — dashboard:

```bash
cd go-honeypot/webapp
node serve.js                 # http://127.0.0.1:5173
```

Open <http://127.0.0.1:5173>, fill in:

- **Host / IP:** `127.0.0.1`
- **Port:** `9090` (control API, not SSH)
- **Auth key:** paste from the banner

Click **Connect**. You get Live / History / Sessions / Services / Config
/ Stats tabs. Config changes from the UI are pushed over the socket and
the daemon starts/stops listeners live.

The Go dashboard's Stats tab is the detailed one: ten KPI tiles (events
retained, last 24 h, last hour, unique attackers, credential attempts,
grants + accept rate, fake shell sessions, sessions, busiest service,
peak hour), seven colour-coded charts (24 h activity with attempts and
grants overlaid, per-service donut, event types, noisiest IPs, targeted
ports, 14-day volume, and a weekday-by-hour heatmap), a per-service
breakdown table, and rankings for credentials, usernames, passwords,
commands, HTTP paths, client fingerprints and source countries. The Live
tab carries a counter strip and a country filter, Sessions can be
filtered by country, state, IP, username, minimum command count and free
text (then sorted by recency, command count or duration), the Services
tab shows the traffic each listener drew, and the PDF report contains all
of it. The top bar shows the server's build and turns into an
**⬆ update available** chip when a newer release is published — clicking
it gives you the exact command to run on the server.

Build a binary instead of `go run`:

```bash
cd go-honeypot/server
CGO_ENABLED=0 go build -o honeypot .
./honeypot --config config.json
```

## Pre-built binaries (Linux / macOS / Windows)

CI (`.github/workflows/go-honeypot.yml`) cross-compiles on every **push
to `main`** and every **PR targeting `main`**:

| OS | Arch | File |
|---|---|---|
| Linux | amd64, arm64 | `honeypot-linux-amd64` / `honeypot-linux-arm64` |
| macOS | amd64, arm64 | `honeypot-darwin-amd64` / `honeypot-darwin-arm64` |
| Windows | amd64, arm64 | `honeypot-windows-amd64.exe` / `honeypot-windows-arm64.exe` |

Pushes to `main` also refresh a GitHub Release tagged `nightly`.

Install the matching binary (detects OS and CPU):

```bash
# Linux / macOS / Git Bash / WSL
GITHUB_REPO=owner/name ./go-honeypot/scripts/install.sh
GITHUB_REPO=owner/name ./go-honeypot/scripts/install.sh --output ./honeypot
```

```powershell
# Windows
$env:GITHUB_REPO = 'owner/name'
.\go-honeypot\scripts\install.ps1
```

```bash
./go-honeypot/scripts/install.sh --repo owner/name --from release
./go-honeypot/scripts/install.sh --from actions            # needs `gh`
./go-honeypot/scripts/install.sh --from actions --pr 42
```

`--repo` is optional if `git remote origin` already points at GitHub.
Private repos / Actions artifacts need `GITHUB_TOKEN`, `GH_TOKEN`, or
`gh auth login`.

## Remote deployment (Go, one command)

`go-honeypot/scripts/deploy-remote.sh` deploys the honeypot onto a fresh
Ubuntu/Debian server and **asks before every step**:

1. picks the pre-built binary matching the server's OS/CPU, checks its
   SHA-256, installs it to `/usr/local/bin/honeypot`
2. moves the real sshd to port **1980** (backup + `sshd -t` fail-safe +
   `ssh.socket` override + listener check)
3. installs and starts the `honeypot-go` systemd service
4. disables the host firewall so the decoy ports answer (or, if you
   decline, just opens the ports it needs)

Run it on the server:

```bash
curl -fsSL https://raw.githubusercontent.com/h4ux/honeystack/main/go-honeypot/scripts/deploy-remote.sh -o deploy-remote.sh
sudo bash deploy-remote.sh
```

Piping works too — prompts come from `/dev/tty`:

```bash
curl -fsSL https://raw.githubusercontent.com/h4ux/honeystack/main/go-honeypot/scripts/deploy-remote.sh | sudo bash
# unattended:
curl -fsSL .../deploy-remote.sh | sudo bash -s -- --yes
```

Useful flags: `--ssh-port`, `--control-port`, `--dir`, `--user`,
`--repo`, `--tag`, `--binary /path/to/honeypot` (skip the download), and
`--skip-binary` / `--skip-ssh` / `--skip-service` / `--skip-firewall`.
Full write-up, including how to undo it:
[go-honeypot/README.md](./go-honeypot/README.md#remote-deployment-in-one-command).

Note: the download needs the `nightly` release, which appears after the
first successful `go-honeypot` CI run on `main`. Until then build the
binary yourself and pass `--binary`.

## Updating the Go server

The dashboard's build chip tells you when a newer release exists. To
apply it, on the server:

```bash
curl -fsSL https://raw.githubusercontent.com/h4ux/honeystack/main/go-honeypot/scripts/update-server.sh | sudo bash
```

It backs the current binary up, verifies the download against the
release `SHA256SUMS`, restarts the service, and rolls back automatically
if the new build does not come up. `--check` compares versions without
changing anything, `--rollback` undoes the last update. Restarting
rotates the auth key, so reconnect the dashboard with the key from
`<install-dir>/data/auth.key`.

## Ubuntu deployment (Go, from a checkout)

```bash
cd go-honeypot
sudo bash setup-ubuntu.sh
```

That script:

1. Moves real sshd from port `22` to `1980` (backup + `sshd -t` fail-safe).
2. Installs Go if missing, builds `server/` into `/usr/local/bin/honeypot`.
3. Grants `CAP_NET_BIND_SERVICE` so the binary can bind ports &lt;1024.
4. Opens `ufw` for real SSH (`1980`), the control API (`9090`), and every
   honeypot port in config.
5. Installs `honeypot-go.service`.

Skip compiling and pull the CI artifact instead (after the first
successful push to `main`):

```bash
sudo GITHUB_REPO=owner/name USE_RELEASE=1 bash setup-ubuntu.sh
```

Then on your laptop run the webapp and connect to
`ws://<server-ip>:9090/api` with the key from:

```bash
sudo cat /opt/go-honeypot/server/data/auth.key
# or
sudo journalctl -u honeypot-go -n 50
```

Reconnect SSH on the new port **before** closing the old session:

```bash
ssh -p 1980 ubuntu@your-server
```

## Go project layout

```
go-honeypot/
├── server/                 daemon (Go)
│   ├── main.go
│   ├── config.default.json
│   └── internal/
│       ├── config/         JSON config
│       ├── eventlog/       ring buffer + NDJSON + pub/sub
│       ├── geoip/          country lookups with an on-disk cache
│       ├── manager/        start/stop/sync services
│       ├── controlapi/     WebSocket API (auth-key gated)
│       └── honeypots/      ssh, telnet, ftp, http, rdp, mysql, vnc, smb,
│                           redis, postgres, clickhouse, mssql, mongodb,
│                           elasticsearch, docker, mqtt, smtp, imap, pop3,
│                           memcached, ldap, rsync, adb, squid/http-proxy,
│                           socks, openvpn, ipsec, wireguard, l2tp, pptp,
│                           sip, dns, snmp, ntp, tftp
├── webapp/                 remote dashboard (static HTML/JS)
│   ├── index.html
│   ├── app.js
│   ├── charts.js           canvas charts for the stats tab
│   ├── pdf.js              in-browser PDF report
│   ├── style.css
│   └── serve.js            `node serve.js` → http://127.0.0.1:5173
├── scripts/
│   ├── deploy-remote.sh    guided server deploy (binary, sshd, service, firewall)
│   ├── update-server.sh    in-place update with checksum + auto-rollback
│   ├── install.sh          download binary for this OS (Linux/macOS)
│   ├── install.ps1         same for Windows PowerShell
│   └── install.cmd
├── setup-ubuntu.sh
└── INSTRUCTIONS.md
```

SSH fake-auth modes are the same JSON shape as Node
(`go-honeypot/server/config.default.json` → `services.ssh.fakeAuth`).

---

# Contributing

- [CONTRIBUTING.md](./CONTRIBUTING.md) — dev setup, the checks CI runs, and
  a step-by-step for adding a honeypot service.
- [SECURITY.md](./SECURITY.md) — how to report a vulnerability privately,
  and what is in scope for a honeypot.
- [SUPPORT.md](./SUPPORT.md) — deployment help and the usual gotchas.
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) · [CHANGELOG.md](./CHANGELOG.md) · [LICENSE](./LICENSE) (MIT)

# Security (both versions)

- Change Node dashboard credentials before exposing port 8080. For Go,
  treat the printed auth key as a password; restarting the daemon
  rotates it.
- Prefer binding the Node dashboard or the Go control API to loopback
  and putting TLS + IP allowlisting in front.
- Never run this on a machine that holds real data.
- The fake SSH shell does **not** execute commands, but isolate the host
  anyway (dedicated VPS, no shared credentials, no access to internal
  networks).
- GeoIP lookups send attacker IPs to a third-party service
  (`ipwho.is` by default). Set `geoip.enabled: false`, or point
  `geoip.url` at your own resolver, if that is not acceptable.
- The open-proxy, mail-relay and VPN emulators never forward, deliver or
  tunnel anything — they answer far enough to record the request and then
  refuse it.
- Some VPS providers forbid honeypot-style traffic — check the ToS.
- Do not run the Node and Go honeypots at the same time on the default
  ports; they will collide on 22/21/23/80/….
