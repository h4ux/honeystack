# go-honeypot

A two-part rewrite of the Node.js honeypot in Go, split into:

- **`server/`** — a single Go binary that runs the honeypot services and
  exposes a WebSocket **control API** protected by a per-run auth key.
- **`webapp/`** — a standalone HTML/CSS/JS webapp (no build step) that
  runs locally (or anywhere) and connects to the server over the
  WebSocket. All settings and live data flow through it.

The daemon prints a fresh auth key on every start:

```
====================================================================
  honeypot daemon started
  control endpoint : ws://<your-server-ip>:9090/api
  auth key         : 8f4a...9c0e   (64-char hex, regenerated per run)
  key file         : data/auth.key
  Connect the local webapp to this endpoint with the auth key above.
====================================================================
```

Open the webapp, paste **host + port + key**, hit Connect, and you have
Live, History, Sessions, Services, Config, and Stats tabs. The layout is
responsive: on phones the tab strip scrolls horizontally, the history
table becomes stacked cards, and the session list and transcript swap
places instead of sitting side by side.

## What the dashboard shows

**Live** — the streaming event feed, with a counter strip above it
(events in buffer, distinct source IPs, credential attempts, how many
were granted, age of the last event, and a colour-coded chip per active
service).

**Services** — one card per listener with its state, port, fake-auth
settings, and the traffic it has actually attracted: events, unique
source IPs, credential attempts, grants, and the last hit.

**Stats** — ten KPI tiles (events retained, last 24 h, last hour, unique
attackers, credential attempts, grants and accept rate, fake shell
sessions, open/retained sessions, busiest service, peak hour) followed by
colour-coded charts:

| Chart | What it plots |
|---|---|
| Activity, last 24 h | hourly events, credential attempts, grants, unique IPs |
| Events by service | donut with per-service colours and shares |
| Event types | ranked bars, coloured by event kind |
| Noisiest source IPs | ranked bars |
| Targeted ports | ranked bars, `port/service` |
| Daily volume | one bar per day, last 14 days |
| When the scanning happens | weekday x hour heatmap (UTC) |

Charts are canvas-drawn, hover for exact values, repaint on resize, and
carry no third-party dependency. Below them: a per-service breakdown
table and rankings for source IPs, services, credentials, usernames,
passwords, commands, requested HTTP paths, and client fingerprints
(user agents / protocol version strings).

## History and reports

- **History tab** — query everything the daemon retains, not just events
  since you opened the page. Filter by time range, service, type, source
  IP, or free-text search across usernames, passwords, commands, and
  details. Export the result as **CSV**.
- **Replay on restart** — on boot the daemon reloads `data/events.ndjson`
  into memory, so connecting after a restart still shows prior activity.
  `storage.maxLogRows` caps how much is kept in memory.
- **PDF report** — the Stats tab (and the History toolbar) generates a
  multi-page PDF: twelve summary metrics, all seven charts repainted
  light-themed at print resolution, the per-service breakdown, and
  rankings for IPs, services, event types, ports, credentials,
  usernames, passwords, commands, HTTP paths and client fingerprints,
  followed by an event table. It is produced in the browser with no
  dependencies, so it works on the Vercel-hosted dashboard too.

## Feature parity with the Node version

- Multi-service honeypots: **SSH, Telnet, FTP, HTTP, RDP, MySQL, VNC,
  SMB, Redis, PostgreSQL, ClickHouse (HTTP + native), MSSQL, MongoDB,
  Elasticsearch, Docker Engine API, and MQTT**.
- Fake SSH shell (Ubuntu-looking prompt, `ls`, `cat`, `whoami`, `uname`,
  `wget`, `sudo`, etc.) — nothing is executed on the host.
- Configurable random-accept auth (modes: `always`, `random`,
  `random-any`, `first-attempt`, `never`).
- Every attempt logged with timestamp, IP, port, username, password,
  and any typed command.
- SSH session transcripts with per-session command count.
- Real-time event feed streamed over WebSocket to the webapp.

### Infrastructure services

| Service | Default port | What is captured |
|---|---:|---|
| ClickHouse HTTP | 8123 | Basic / `X-ClickHouse-*` credentials, database, SQL |
| ClickHouse native | 9000 | client hello, version strings, query-like payloads |
| MSSQL / TDS | 1433 | prelogin metadata, LOGIN7 username/password/app/database, SQL batches |
| MongoDB wire | 27017 | hello/commands, SCRAM username and proof payload |
| Elasticsearch | 9200 | Basic credentials, REST route, query/bulk body |
| Docker Engine API | 2375 | unauthenticated API discovery and mutating requests |
| MQTT | 1883 | CONNECT credentials/client ID, topics, publishes/subscriptions |

The emulators never execute submitted SQL, shell commands, container
actions, or message payloads.

Needs **Go 1.22+**. The module path is `honeypot` (local). Do not use
`github.com/example/honeypot` — that is not a real repository and `sudo`
builds will try to clone it from GitHub.

## Quick start (locally)

Terminal 1 — start the server:

```bash
cd server
GOTOOLCHAIN=local go run . --config config.json
```

The banner will print your auth key. Note the `port` it listens on
(defaults to `:9090`). If you want to use unprivileged ports, edit
`config.json` before starting (e.g. set `ssh.port` to `2222`).

Terminal 2 — serve the webapp:

```bash
cd webapp
node serve.js         # http://127.0.0.1:5173
```

Open <http://127.0.0.1:5173>, fill in host `127.0.0.1`, port `9090`,
paste the auth key, click Connect.

You can also open `webapp/index.html` directly via `file://` — the
WebSocket connection to the server will still work — but the tiny
`serve.js` is handier because it gives you a normal URL.

## Host the dashboard on Vercel

The webapp is static and generic: anyone can paste **host + port + auth
key** of a running Go daemon.

1. Import [h4ux/honeystack](https://github.com/h4ux/honeystack) in Vercel.
2. Set **Root Directory** to `go-honeypot/webapp`.
3. Framework preset: **Other**. No build command, no output directory.
4. Deploy.

`webapp/api/proxy.js` is deployed as a serverless function at
`/api/proxy`. It relays REST calls so an `https://` page can reach a
plain `http://` control API (browsers block mixed `ws://` and `http://`
from HTTPS).

**Analytics** — `index.html` already loads the Vercel Web Analytics and
Speed Insights scripts. Turn both on in the Vercel dashboard under
*Project → Analytics* and *Speed Insights*; no code change needed. The
scripts are served by Vercel at `/_vercel/...` and are inert anywhere
else.

On the connect form, keep **use HTTPS relay** checked when the dashboard
is on Vercel. The Go process must be reachable from the internet on the
control port (default 9090).

Direct WebSocket still works for local `http://` pages, or if you put
TLS on the control port (`control.tlsCertFile` / `tlsKeyFile`) and check
**use wss://**.

## Pre-built binaries (Linux / macOS / Windows)

Every push and PR to `main` runs `.github/workflows/go-honeypot.yml`,
which cross-compiles a static binary for:

| OS      | Architectures     | Artifact name                          |
|---------|-------------------|----------------------------------------|
| Linux   | amd64, arm64      | `honeypot-linux-amd64` / `-arm64`      |
| macOS   | amd64, arm64      | `honeypot-darwin-amd64` / `-arm64`     |
| Windows | amd64, arm64      | `honeypot-windows-amd64.exe` / `-arm64.exe` |

Pushes to `main` also publish (or refresh) a GitHub Release tagged
`nightly`. PRs only upload workflow artifacts.

Download the matching binary with the install script — it detects your
OS and CPU:

```bash
# Linux / macOS / Git Bash / WSL
GITHUB_REPO=owner/name ./go-honeypot/scripts/install.sh
# or, from inside go-honeypot/
GITHUB_REPO=owner/name ./scripts/install.sh --output ./honeypot
```

```powershell
# Windows (PowerShell)
$env:GITHUB_REPO = 'owner/name'
.\go-honeypot\scripts\install.ps1
# or double-click scripts\install.cmd
```

Useful flags:

```bash
./scripts/install.sh --repo owner/name --output /usr/local/bin/honeypot
./scripts/install.sh --from release            # GitHub Release only
./scripts/install.sh --from actions            # latest successful Actions run (needs `gh`)
./scripts/install.sh --from actions --pr 42    # artifacts from a PR
./scripts/install.sh --run-id 123456789
```

If the repo has a `git remote origin` pointing at GitHub, `--repo` is
optional. For private repos or Actions artifacts, export `GITHUB_TOKEN`
or `GH_TOKEN` (or run `gh auth login`).

## Remote deployment in one command

`scripts/deploy-remote.sh` is meant to be run **on the server** — including
straight off the internet — and it **asks before every change**:

1. **Pick the right binary.** Detects the machine's OS and CPU, finds the
   matching `honeypot-<os>-<arch>` asset in the GitHub release, verifies
   its SHA-256 against the published `SHA256SUMS`, installs it to
   `/usr/local/bin/honeypot`, and drops `config.default.json` /
   `config.json` into the install root.
2. **Move the real sshd to port 1980.** Backs up `sshd_config`, rewrites
   `Port` (including `sshd_config.d/*.conf` drop-ins and socket-activated
   `ssh.socket` on newer Ubuntu), validates with `sshd -t` and restores
   the backup if that fails, restarts sshd, confirms it is listening, and
   waits for you to prove a new session works before going on.
3. **Install and start the service.** Creates the `honeypot` system
   account, `<dir>/data`, and a `honeypot-go.service` unit that grants
   only `CAP_NET_BIND_SERVICE`, then enables and starts it.
4. **Disable the host firewall.** A honeypot is only useful if the decoy
   ports answer, so this turns `ufw` / `firewalld` off, sets the iptables
   policies to ACCEPT and (if you agree) flushes nftables. Decline it and
   it offers to open just the needed ports in `ufw` instead.

```bash
# download first, then run — you can read it before it touches anything
curl -fsSL https://raw.githubusercontent.com/h4ux/honeystack/main/go-honeypot/scripts/deploy-remote.sh -o deploy-remote.sh
sudo bash deploy-remote.sh
```

```bash
# or pipe it straight in; prompts are read from /dev/tty, so they still work
curl -fsSL https://raw.githubusercontent.com/h4ux/honeystack/main/go-honeypot/scripts/deploy-remote.sh | sudo bash
```

```bash
# unattended: answer yes to everything
curl -fsSL https://raw.githubusercontent.com/h4ux/honeystack/main/go-honeypot/scripts/deploy-remote.sh | sudo bash -s -- --yes
```

Flags:

| Flag | Meaning |
|---|---|
| `-y`, `--yes` | assume yes for every question (needed when there is no terminal) |
| `--repo OWNER/NAME` | repo to download from (default `h4ux/honeystack`) |
| `--tag TAG` | release tag (default `nightly`; falls back to the newest release) |
| `--binary PATH` | install a local binary instead of downloading |
| `--ssh-port N` | port the real sshd moves to (default `1980`) |
| `--control-port N` | control API port (default `9090`) |
| `--dir PATH` | install root (default `/opt/honeystack`) |
| `--user NAME` | system account that runs the daemon (default `honeypot`) |
| `--skip-binary`, `--skip-ssh`, `--skip-service`, `--skip-firewall` | leave that step alone |

The script needs the `nightly` release to exist, which happens after the
first successful `go-honeypot` workflow run on `main`. Until then, build
locally and hand it the file:

```bash
cd go-honeypot/server && CGO_ENABLED=0 go build -o /tmp/honeypot .
scp /tmp/honeypot user@server:/tmp/honeypot
sudo bash deploy-remote.sh --binary /tmp/honeypot
```

It finishes by printing the SSH command for the new port, the control
endpoint, the auth key, how to connect the dashboard, and how to undo
everything:

```bash
sudo systemctl disable --now honeypot-go
sudo cp /etc/ssh/sshd_config.honeystack-backup.* /etc/ssh/sshd_config
sudo systemctl restart ssh
sudo ufw enable          # if the firewall was disabled
```

Only run this on a throwaway host: after step 4 nothing on the machine is
filtered, including the real sshd on port 1980 — keep key-only auth on.
Cloud security groups are separate and still have to be opened by hand.

## Ubuntu deployment

See [INSTRUCTIONS.md](./INSTRUCTIONS.md). One-liner:

```bash
sudo bash setup-ubuntu.sh
```

It moves the real sshd to port `1980` (fail-safe), installs the binary,
opens the firewall, and installs a `honeypot-go.service` systemd unit.

To skip compiling on the server and pull the CI artifact instead:

```bash
sudo GITHUB_REPO=owner/name USE_RELEASE=1 bash setup-ubuntu.sh
```

## Auth model

- On every start the server generates a 32-byte random token, hex-encodes
  it (64 chars) and writes it to `data/auth.key` (mode 0600).
- Clients pass the token in the WebSocket URL:
  `ws://host:port/api?token=<AUTH_KEY>`
- The token is compared with `crypto/subtle.ConstantTimeCompare`.
- The server does **not** enforce origin — the auth key is the only
  thing that matters. If you need TLS, front the control port with
  nginx/caddy and check the `use wss://` box in the webapp connect
  form.

## Protocol

The WebSocket exchanges JSON messages of shape:

```jsonc
// client → server (request)
{ "type": "get_events", "reqId": "r1", "payload": { "limit": 200 } }

// server → client (response)
{ "type": "get_events:reply", "reqId": "r1", "payload": [ ... events ... ] }

// server → client (broadcast, no reqId)
{ "type": "event", "payload": { "service": "ssh", "type": "command", ... } }

// server → client (initial snapshot)
{ "type": "hello", "payload": { "config": ..., "services": ..., "stats": ..., "events": ... } }
```

Supported request types:

| type              | payload                              | reply                        |
|-------------------|--------------------------------------|------------------------------|
| `get_config`      | –                                    | `Config`                     |
| `update_config`   | `Config`                             | `Config` (post-merge)        |
| `list_services`   | –                                    | `[]{name,running,port,error}`|
| `get_stats`       | –                                    | `Stats`                      |
| `get_events`      | `{service?,type?,ip?,q?,limit?,since?,until?}` | `[]Event`         |
| `get_sessions`    | `{service?,limit?}`                  | `[]Session`                  |
| `get_session`     | `{id}`                               | `Session` w/ events          |
| `get_range`       | –                                    | `{oldest,newest}` (ms)       |
| `ping`            | –                                    | `{pong: <ms>}`               |

The same operations are available over REST for clients that cannot hold
a WebSocket (this is what the Vercel relay uses). Pass the key as
`Authorization: Bearer <key>`, `X-Auth-Key: <key>`, or `?token=`:

| Method | Path | Notes |
|---|---|---|
| GET | `/health` | unauthenticated liveness probe |
| GET | `/v1/hello` | config + services + stats + recent events |
| GET | `/v1/events` | `service, type, ip, q, since, until, limit` |
| GET | `/v1/range` | oldest/newest retained timestamps |
| GET | `/v1/sessions` | `service, limit` |
| GET | `/v1/session?id=` | one session with its events |
| GET | `/v1/stats` | aggregate counters |
| GET | `/v1/services` | listener status |
| GET/PUT | `/v1/config` | read or replace the config |

## Project layout

```
go-honeypot/
├── server/
│   ├── main.go
│   ├── config.default.json
│   ├── go.mod / go.sum
│   └── internal/
│       ├── config/           JSON config with default merge
│       ├── eventlog/         in-memory ring + NDJSON append + pub/sub
│       ├── manager/          register/start/stop/sync services
│       ├── controlapi/       WebSocket control API (auth-token-gated)
│       └── honeypots/
│           ├── base.go       TCP framework
│           ├── ssh.go        + ssh_shell.go  (gliderlabs/ssh + fake shell)
│           ├── telnet.go
│           ├── ftp.go
│           ├── http.go
│           ├── rdp.go
│           ├── mysql.go
│           ├── vnc.go
│           ├── smb.go
│           ├── redis.go
│           ├── postgres.go
│           ├── clickhouse_native.go
│           ├── mssql.go
│           ├── mongodb.go
│           ├── mqtt.go
│           └── http_services.go     ClickHouse HTTP, Elasticsearch, Docker
├── webapp/
│   ├── index.html
│   ├── style.css
│   ├── app.js
│   ├── charts.js             canvas charts (timeline, donut, bars, heatmap)
│   ├── pdf.js                in-browser PDF report writer
│   └── serve.js              zero-dep static server for local hosting
├── scripts/
│   ├── install.sh            download the binary for this OS (Linux/macOS)
│   ├── install.ps1           same for Windows PowerShell
│   └── install.cmd
├── setup-ubuntu.sh
├── INSTRUCTIONS.md
└── README.md
```

## Storage

Instead of SQLite (would require CGO), the Go version keeps:

- an in-memory **ring buffer** of the last N events (default 200 000),
- an append-only **`events.ndjson`** file for durable history.

This keeps the binary a single static file and avoids any C toolchain.

## License

MIT.
