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

> Internals: [docs/architecture.md](../docs/architecture.md) explains the
> packages, the probe→event path and the goroutine/lock map;
> [docs/storage.md](../docs/storage.md) documents every file it writes and
> the pattern used for each.

## What the dashboard shows

**Live** — the streaming event feed, with a counter strip above it
(events in buffer, distinct source IPs, credential attempts, how many
were granted, age of the last event, and a colour-coded chip per active
service). Filter by service, type, IP or country.

**Sessions** — filter by free text (id, IP, username, country, network
operator), service, country, state (active/closed), source IP, username
and minimum command count, then sort by newest, oldest, most commands or
longest. The list shows each session's country, duration, command count
and network operator; the footer summarises what matched. Filtering
happens on the daemon, so a busy honeypot does not ship thousands of
sessions to the browser just to hide most of them.

**Services** — one card per listener with its state, port, fake-auth
settings, and the traffic it has actually attracted: events, unique
source IPs, credential attempts, grants, and the last hit.

**Stats** — thirteen KPI tiles (events retained, last 24 h, last hour,
unique attackers, credential attempts, grants and accept rate, fake shell
sessions, open/retained sessions, busiest service, peak hour, **uptime
this run**, **first hit after start**, countries seen) followed by
colour-coded charts:

| Chart | What it plots |
|---|---|
| Activity, last 24 h | hourly events, credential attempts, grants, unique IPs |
| Events by service | donut with per-service colours and shares |
| Event types | ranked bars, coloured by event kind |
| Noisiest source IPs | ranked bars |
| Targeted ports | ranked bars, `port/service` |
| Source countries | ranked bars with flags, unique IPs per country |
| Daily volume | one bar per day, last 14 days |
| When the scanning happens | weekday x hour heatmap (UTC) |

Charts are canvas-drawn, hover for exact values, repaint on resize, and
carry no third-party dependency. Below them: a per-service breakdown
table and rankings for source IPs, services, credentials, usernames,
passwords, commands, requested HTTP paths, and client fingerprints
(user agents / protocol version strings), plus source countries with
their unique-IP counts.

### Long payloads

Dropper one-liners run to several kilobytes. Tables clamp them to a single
line with a size badge and a **view** pill; the live feed clamps to two
lines. The pill opens the full text in a dialog with the event's service,
type, source IP, country and timestamp, a wrap toggle and a copy button.
Cells cannot widen a table any more (`table-layout: fixed`), so one 4 KB
command no longer pushes the layout past the viewport on desktop or phone.
CSV and PDF exports still carry the untruncated text.

### This run vs. everything retained

The event ring is rehydrated from `events.ndjson` on boot, so most
counters describe traffic from previous runs too. These separate the
current run out:

- **Uptime this run** — ticks live, with the daemon's start time
  underneath, and repeated in the window line above the tiles.
- **First hit after start** — how long the box sat untouched before the
  first *inbound* event, which service it landed on, and how many hits
  the run has seen. The daemon's own startup bookkeeping (`startup`,
  `service_started`, …) does not count as a hit, so this measures real
  exposure time. Until something arrives it reads `waiting`, counting up.
- **Per-service breakdown** gains *This run* (events since start) and
  *1st hit after start* (`+2m 14s`, or `not yet · <how long quiet>` for a
  listener nothing has touched yet).

All three are in the PDF report as well. The API exposes them as
`startedAt`, `uptimeMs`, `eventsSinceStart`, `trafficSinceStart`,
`firstEventSinceStart`, `timeToFirstEventMs`, `firstEventService`, and
per service `eventsSinceStart` / `firstSinceStart` / `timeToFirstMs`.

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

- Multi-service honeypots — **41 listeners** out of the box across six
  families:
  - *Remote access / shells:* SSH, Telnet, RDP, VNC, ADB (Android Debug
    Bridge)
  - *Files and directories:* FTP, SMB, rsync, TFTP, LDAP
  - *Databases and caches:* MySQL, PostgreSQL, MSSQL, MongoDB, Redis,
    Memcached, Elasticsearch, ClickHouse (HTTP + native)
  - *Web and orchestration:* HTTP, Docker Engine API, MQTT
  - *Mail:* SMTP (25), SMTP submission (587), IMAP, POP3
  - *Proxies:* Squid-style HTTP proxy (3128), HTTP proxy (8080), SOCKS4/5
  - *VPN and infrastructure:* OpenVPN (UDP+TCP), IPsec/IKE (500, 4500),
    WireGuard, L2TP, PPTP, SIP (UDP+TCP), DNS, SNMP, NTP
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

### Mail services

| Service | Default port | What is captured |
|---|---|---|
| SMTP | 25 | EHLO, `AUTH LOGIN`/`PLAIN` credentials (base64-decoded), `MAIL FROM`/`RCPT TO` relay attempts, message bodies |
| SMTP submission | 587 | same emulator on the submission port |
| IMAP | 143 | `LOGIN` and `AUTHENTICATE PLAIN/LOGIN` credentials, mailbox commands |
| POP3 | 110 | `USER`/`PASS`, `APOP` digests, `CAPA` |

Relay probes are answered with `250 Ok` right through `DATA`, because an
apparently-open relay is what a spam scanner is looking for — the message
is logged and discarded, never delivered.

### Proxy services

| Service | Default port | What is captured |
|---|---|---|
| Squid-style proxy | 3128 | `CONNECT host:port` targets, absolute-URI requests, `Proxy-Authorization` credentials, User-Agent |
| HTTP proxy | 8080 | same emulator on the other common proxy port |
| SOCKS | 1080 | SOCKS4/4a userid + destination, SOCKS5 username/password (RFC 1929) and requested host:port |

Every proxy request is refused (`403` / SOCKS "not allowed") — nothing is
ever forwarded. Each event records where the client wanted to go, and
`details.intent` labels the well-known abuse pattern behind the port
(`spam relay` for 25/465/587, `ssh tunnel` for 22, and so on).

### VPN and infrastructure services

| Service | Default port | What is captured |
|---|---|---|
| OpenVPN | 1194/udp + 1194/tcp | hard-reset opcode, client session id; answers with a server reset so the client keeps talking |
| IPsec IKE | 500/udp, 4500/udp | IKEv1/v2 exchange type, initiator SPI, NAT-T detection; replies `NO_PROPOSAL_CHOSEN` |
| WireGuard | 51820/udp | handshake-initiation type and sender index (stays silent, like a real peer) |
| L2TP | 1701/udp | control/data flag, version, client hostname strings |
| PPTP | 1723 | Start-Control-Connection request, hostname and vendor strings; answers with a plausible reply |
| SIP | 5060/udp + 5060/tcp | REGISTER/INVITE/OPTIONS, digest `Authorization` username + response, `From`/`To`, toll-fraud flag on INVITE |
| DNS | 53/udp (off by default) | queried name and type, ANY/TXT amplification flag; answers NXDOMAIN only |
| SNMP | 161/udp | community string (logged as a credential), PDU type, first OID; the reply is never larger than the request |
| NTP | 123/udp | client requests get a normal answer; mode 6/7 (monlist) is logged as `amplification_attempt` and never answered |
| TFTP | 69/udp | requested filename (read) or upload attempt (write), answered with an error |

None of the UDP emulators can be used as an amplifier: replies are either
absent or no larger than the request.

DNS ships **disabled** because `systemd-resolved` already owns port 53 on
a typical Ubuntu box. Enable it after freeing the port (set
`DNSStubListener=no` in `/etc/systemd/resolved.conf`).

## What it stores, where, and for how long

Nothing is stored in a database. There are four places data lives, and
each one is bounded:

| Where | What | Retention | Cost |
|---|---|---|---|
| **Memory ring** | the last `storage.maxLogRows` events (default **25,000**) | until pushed out by newer events | ~1–3.5 KB per event, so ~40–90 MB at the default |
| **Session table** | one row per connection (or per 2-minute UDP burst): id, service, source, username, command count | oldest **closed** sessions are dropped past `storage.maxSessions` (default **20,000**) | ~260 bytes each, ~5 MB at the default |
| **`data/events.ndjson`** | every event, one JSON object per line | rotated at `storage.maxLogFileMb` (default **128 MB**), keeping one previous generation as `events.ndjson.1` | ≤ ~256 MB on disk |
| **`data/geoip-cache.json`** | country/ASN per IP | `geoip.ttlHours` (default 30 days) | ~150 bytes per IP |

Per-event capture is capped too: `storage.maxDetailBytes` (default
**2048**) is the ceiling for an event's whole `details` map, and HTTP
bodies are read at most 16 KB before that cap applies. Without it a
single scanner posting large bodies pins hundreds of MB in the ring.

Events also stream to connected dashboards, and a filtered subset goes to
stdout — see `storage.stdoutEvents` below.

### Measured footprint

A 20-second flood (≈54,000 events: ~900 connections/second across all 41
listeners, 16k HTTP POSTs with 64 KB bodies, 2k UDP probes) on one core:

| | Idle | During the flood | Settled after |
|---|---|---|---|
| RSS | 13 MB | 96 → 152 MB | 152 MB (84 MB live heap) |
| CPU | 0.1% of a core (dashboard polling every 2s) | 11% of a core | 0.1% |
| Ring | 0 | 25,000 events (capped) | 25,000 |
| Sessions | 0 | 17,066 (capped at 20,000) | 17,066 |
| Journal lines | — | 807 for 54,000 events | — |

RSS sits above the live heap because Go returns memory to the OS lazily;
`GOMEMLIMIT` (set to 192 MiB by the deploy script) keeps that bounded and
makes the collector work harder instead of the kernel OOM-killing the
daemon.

### Tuning knobs

```jsonc
"storage": {
  "logFile": "data/events.ndjson",
  "maxLogRows": 25000,        // events in memory — the main RAM dial
  "maxSessions": 20000,       // rows in the session table
  "maxDetailBytes": 2048,     // per-event capture ceiling
  "maxLogFileMb": 128,        // rotate the NDJSON past this (-1 = never)
  "statsCacheMs": 3000,       // serve the aggregate from cache this long
  "stdoutEvents": "important" // journal volume: important | all | none
}
```

- **`maxLogRows`** is the dial that matters: heap ≈ `maxLogRows` × 1–3.5 KB
  depending on how much of your traffic is HTTP with bodies.
- **`statsCacheMs`** exists because computing the aggregate walks the whole
  ring (~35 ms at 25k events) and every open dashboard asks on a timer.
  Cached it is ~0.4 ms.
- **`stdoutEvents`** defaults to `important` (credentials, commands,
  relay/proxy attempts, amplification, errors). `all` writes a journal
  line per event — on a scanned host that is a real CPU and disk cost.
  `none` turns it off entirely.

### Sizing profiles

| Box | `maxLogRows` | `maxSessions` | `GOMEMLIMIT` | Expected RSS |
|---|---|---|---|---|
| 512 MB VPS | 10000 | 5000 | 96MiB | ~60–90 MB |
| 1 GB VPS (default) | 25000 | 20000 | 192MiB | ~110–160 MB |
| 4 GB+ | 100000 | 50000 | 768MiB | ~400–600 MB |

Reducing `maxLogRows` does not lose history: the dashboard's History tab
queries the ring, but `events.ndjson` keeps everything until rotation, and
the ring is refilled from its tail on restart.

## Country lookups (GeoIP)

Every event and session carries the source country when it is known:

```jsonc
"geoip": {
  "enabled": true,
  "provider": "ipwho.is",          // or ip-api, ipinfo, or a custom url
  "cacheFile": "data/geoip-cache.json",
  "ttlHours": 720,
  "timeoutMs": 4000,
  "rateLimitPerMin": 40
}
```

- Lookups run on a background worker, so a honeypot handler never waits on
  the network. Events are annotated at log time when the IP is already
  cached, and on the way out to the dashboard once the lookup lands.
- Results are cached in memory and on disk (`data/geoip-cache.json`), so
  each IP is asked about once per `ttlHours` (30 days by default).
- Private, loopback and link-local addresses are labelled locally and
  never sent anywhere.
- The dashboard shows a flag + ISO code next to every IP, adds a country
  filter to Live, History and Sessions, and a "Source countries" chart,
  table and KPI tile to Stats. The `/v1/geo?ips=a,b,c` endpoint (or the
  `geo_lookup` WebSocket action) resolves a batch on demand.
- **Privacy:** attacker IPs are sent to the configured provider. Set
  `geoip.enabled` to `false` to keep every address on the box; the
  dashboard then shows `··` instead of a flag. Point `geoip.url` at your
  own service (with an `{ip}` placeholder) to self-host the lookup.

## A stable address on a changing IP

A honeypot on a dynamic IP silently breaks every bookmark when it is
renumbered. The daemon tracks its own public address, records every change,
and — when a dynamic-DNS credential is configured — keeps a hostname
pointed at it.

```jsonc
"dyndns": {
  "enabled": true,
  "provider": "sslip.io",                   // sslip.io | xyz.frl | duckdns | noip | custom
  "credentialsFile": "data/dyndns.json",    // 0600, written at install time
  "intervalMinutes": 5,
  "ipCheckUrls": ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"],
  "historyFile": "data/ip-history.json",
  "maxHistory": 200
}
```

Every `intervalMinutes` the daemon asks an echo service for its address
(first one that answers with a valid IP wins) and pushes it to the
provider. On a change it appends to `data/ip-history.json`, logs a
`public_ip_changed` event — so it appears in the live feed, history and
PDF like anything else — and refreshes the systemd status line.

**Where you see it:**

- **Startup banner**, so `journalctl -u honeypot-go` answers "what is the
  URL again?":
  ```
  public address   : https://8355e9ec….xyz.frl   (dyndns: xyz.frl, refreshed every 5m)
  ```
- **`systemctl status honeypot-go`**, via `sd_notify`. The unit sets
  `NotifyAccess=main` and the daemon publishes a status line that tracks
  the current address:
  ```
  Status: "https://8355e9ec….xyz.frl · 203.0.113.9 · control :9090 · 41 listeners"
  ```
- **Dashboard → Stats → Public address**: the hostname as a link, current
  IP, number of changes, when it was last checked/changed, the last update
  result, and a table of every change (when, new address, previous
  address, which echo service saw it, what the provider answered).
- **`GET /v1/pubaddr`** (or the `get_pubaddr` action) for the same data.

### Providers

There are two kinds. **Derived** providers need no account, no credential
and no update request at all — the address is encoded in the name, so the
daemon just computes it. **Registered** providers give you a name that
stays the same across IP changes, at the cost of holding a credential.

| Provider | Kind | Signup | Request |
|---|---|---|---|
| `sslip.io` (default) | derived | none | none — `62-228-88-158.sslip.io` resolves to `62.228.88.158` |
| `nip.io`, `traefik.me` | derived | none | none — same scheme, different zone |
| `xyz.frl` | registered | none (anonymous `GET /generate`) | `https://xyz.frl/nic/update?myip={ip}` + basic auth |
| `duckdns` | registered | **yes** — OAuth login (GitHub/Google/…) for a token | `https://www.duckdns.org/update?domains={hostname}&token={password}&ip={ip}` |
| `noip` | registered | **yes** | `https://dynupdate.no-ip.com/nic/update?hostname={hostname}&myip={ip}` + basic auth |
| anything else | registered | depends | `https://<provider>/nic/update?myip={ip}` + basic auth |

`updateUrl` overrides the template entirely; `{ip}`, `{hostname}`,
`{username}` and `{password}` are substituted, and credentials are also
sent as HTTP basic auth.

**Which to pick.** `sslip.io` is the default because it works with nothing
but the config line: it always resolves, there is no account, no token and
no outbound update call. The trade is that the name changes when the
address does — the dashboard, the banner and `systemctl status` always
show the current one, and every change is in the log, so you re-copy the
URL after a change rather than keeping a permanent bookmark. If you want a
name that never changes, either use a provider you already have (point
`updateUrl` at Cloudflare, your registrar's API, DuckDNS after a 30-second
login) or try `xyz.frl`, noting the caveat below.

> **Caveat on xyz.frl.** `scripts/deploy-remote.sh` can mint a free,
> anonymous hostname there (`GET https://xyz.frl/generate`), and the
> service accepts updates (`HTTP 202`). At the time of writing the
> generated names did **not** resolve — the authoritative nameserver
> answered `NXDOMAIN` for a freshly updated hostname, with both a
> documentation IP and a real public IP, minutes after a successful
> update. Treat the hostname as best-effort until you have confirmed it
> resolves for you (`getent hosts <name>`), and switch `provider` to
> DuckDNS or your own DNS if it does not. **IP tracking, the change log
> and the status line work regardless of the provider** — that part does
> not depend on anyone publishing a record.

Rate limits are respected: updates are never sent more than once a minute,
`429` is recorded as `rate-limited` and retried on the next tick, and
`401` shows as `unauthorized` rather than being retried blindly.

**Privacy:** enabling this tells an IP-echo service and your DNS provider
this host's address. Set `dyndns.enabled` to `false` to keep everything
local; nothing else changes.

## Version check and updating

The daemon reports what it is (`/v1/version`, and in the `hello` payload):
version, commit, Go version, platform, uptime, listener count, and the
repository it was built from. The dashboard compares that commit with the
latest published release and shows either the build id or an
**⬆ update available** chip in the top bar. Clicking it opens the build
panel with copy-paste update instructions.

On the server:

```bash
# fetch it once (no pipe: a failed download cannot silently run nothing)
curl -fsSL --show-error https://raw.githubusercontent.com/h4ux/honeystack/main/go-honeypot/scripts/update-server.sh -o update-server.sh

sudo bash update-server.sh --check    # compare versions only (exit 10 = update available)
sudo bash update-server.sh            # update: backup, swap, restart, auto-rollback
sudo bash update-server.sh --rollback # undo the last update
```

The short pipe form works too — keep `--show-error` so a download failure
is reported instead of running an empty script:

```bash
curl -fsSL --show-error https://raw.githubusercontent.com/h4ux/honeystack/main/go-honeypot/scripts/update-server.sh | sudo bash
```

`update-server.sh` finds the install from the `honeypot-go` systemd unit,
verifies the download against the release `SHA256SUMS`, keeps the last
three binaries as `honeypot.bak-<timestamp>`, and restores the previous
one if the new build fails to come up. Restarting rotates the auth key,
so reconnect the dashboard with the key from
`<install-dir>/data/auth.key`.

Flags: `--check`, `--force`, `--rollback`, `--yes`, `--repo`, `--tag`,
`--binary`, `--service`, `--path`, `--keep`.

Needs **Go 1.25+** (`golang.org/x/crypto` v0.52.0 sets that floor). The
module path is `github.com/h4ux/honeystack/go-honeypot/server`. Ubuntu
ships an older Go, so leave `GOTOOLCHAIN` on its default `auto` and the
distro toolchain will fetch the matching one on first build — or skip
compiling altogether and install the release binary.

## Quick start (locally)

Terminal 1 — start the server:

```bash
cd server
go run . --config config.json
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
curl -fsSL --show-error https://raw.githubusercontent.com/h4ux/honeystack/main/go-honeypot/scripts/deploy-remote.sh -o deploy-remote.sh
sudo bash deploy-remote.sh
```

```bash
# or pipe it straight in; prompts are read from /dev/tty, so they still work
curl -fsSL --show-error https://raw.githubusercontent.com/h4ux/honeystack/main/go-honeypot/scripts/deploy-remote.sh | sudo bash
```

```bash
# unattended: answer yes to everything
curl -fsSL --show-error https://raw.githubusercontent.com/h4ux/honeystack/main/go-honeypot/scripts/deploy-remote.sh | sudo bash -s -- --yes
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

## API additions

| Endpoint | WebSocket action | Purpose |
|---|---|---|
| `GET /v1/version` | `get_version` | build info: version, commit, Go, platform, uptime, listeners, repo |
| `GET /v1/geo?ips=a,b` | `geo_lookup` | resolve a batch of IPs to country/city/ASN from the cache |
| `GET /v1/sessions?...` | `get_sessions` | now takes `service`, `ip`, `username`, `country`, `status`, `minCommands`, `since`, `until`, `q`, `sort`, `limit` |

The `hello` payload also carries `build` and `geo` blocks, which is what
the dashboard uses for the version chip and the GeoIP status line.

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
