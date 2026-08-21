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
Live, History, Sessions, Services, Config, and Stats tabs.

## History and reports

- **History tab** — query everything the daemon retains, not just events
  since you opened the page. Filter by time range, service, type, source
  IP, or free-text search across usernames, passwords, commands, and
  details. Export the result as **CSV**.
- **Replay on restart** — on boot the daemon reloads `data/events.ndjson`
  into memory, so connecting after a restart still shows prior activity.
  `storage.maxLogRows` caps how much is kept in memory.
- **PDF report** — the Stats tab (and the History toolbar) generates a
  multi-page PDF with the summary metrics, both charts as images, top
  IPs, services, event types, credentials, commands, and an event table.
  It is produced in the browser with no dependencies, so it works on the
  Vercel-hosted dashboard too.

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
