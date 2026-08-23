# Files, paths and the saving pattern

There is no database. Everything the daemon keeps is a plain file under one
install directory, plus a bounded ring in memory. This page lists every
path, what writes it and when, how durable it is, and what it costs.

Architecture and data flow: [architecture.md](./architecture.md).

## Layout

Paths in the config are **relative to the daemon's working directory**,
which is the install directory (`WorkingDirectory=` in the systemd unit).
`scripts/deploy-remote.sh` uses `/opt/honeystack`; a source checkout uses
`go-honeypot/server`.

```
/opt/honeystack/                     ← WorkingDirectory (0755, root-owned)
├── config.default.json              shipped defaults, read-only reference
├── config.json                      the live config (the daemon writes this)
└── data/                            0750, owned by the service account
    ├── auth.key                     0600, new random key every start
    ├── events.ndjson                append-only event log
    ├── events.ndjson.1              one rotated generation
    ├── geoip-cache.json             IP → country cache
    ├── dyndns.json                  0600, dynamic-DNS credentials
    ├── ip-history.json              this host's public IP over time
    └── ssh_host_ed25519_key         0600, generated once, then stable

/usr/local/bin/honeypot              the binary
/usr/local/bin/honeypot.bak-<ts>     up to 3 kept by update-server.sh
/etc/systemd/system/honeypot-go.service
/etc/ssh/sshd_config.honeystack-backup.<ts>   from the deploy script
```

Which paths the daemon uses is configurable:

```jsonc
"storage": {
  "logFile":     "data/events.ndjson",
  "hostKeyFile": "data/ssh_host_ed25519_key"
},
"control": { "authKeyFile": "data/auth.key" },
"geoip":   { "cacheFile":   "data/geoip-cache.json" },
"dyndns":  { "credentialsFile": "data/dyndns.json",
             "historyFile":     "data/ip-history.json" }
```

## Every file, and the pattern it is written with

| Path | Written by | When | Pattern | Mode |
|---|---|---|---|---|
| `config.json` | `internal/config` | first run, then every dashboard config change | **temp + rename** (atomic) | 0644 |
| `data/events.ndjson` | `internal/eventlog` | every event | **append-only**, buffered, flushed every 500 ms | 0644 |
| `data/events.ndjson.1` | `internal/eventlog` | when the log passes `maxLogFileMb` | rename, replacing any previous generation | 0644 |
| `data/auth.key` | `internal/controlapi` | once per process start | truncate + write | **0600** |
| `data/ssh_host_ed25519_key` | `internal/honeypots` (ssh) | first SSH start only | write if absent | **0600** |
| `data/geoip-cache.json` | `internal/geoip` | every 2 min if dirty, and on shutdown | **temp + rename** (atomic) | 0644 |
| `data/ip-history.json` | `internal/pubaddr` | on every public-IP change | **temp + rename** (atomic) | 0644 |
| `data/dyndns.json` | the installer (or you) | once, at install | **temp + rename** (atomic) | **0600** |

Three different patterns, chosen per file:

- **Append-only** for the event log. Events are immutable, so appending is
  the cheapest durable thing and a partial line at the tail is
  recoverable — the replay path skips lines that do not parse.
- **Temp + rename** for the files that are *replaced* wholesale
  (`config.json`, `geoip-cache.json`, `ip-history.json`, `dyndns.json`).
  `rename(2)` is atomic within a filesystem, so a crash mid-write leaves
  the previous version intact rather than a truncated file the daemon
  cannot parse on boot.
- **Write-once** for the secrets. The auth key is rewritten each start (it
  is meant to rotate); the SSH host key is written only if missing, so an
  attacker sees a stable host fingerprint across restarts.

### Durability of the event log

Writes go through a `bufio.Writer`, and a flusher goroutine calls `Flush`
every 500 ms; `Sync` (fsync) happens only on shutdown. A hard power loss
can therefore lose up to the last half second of events. That is a
deliberate trade: fsync per event would cap throughput at disk latency,
and a honeypot's value is in aggregate patterns, not in the last packet
before the plug was pulled. Graceful stop (`systemctl stop`, SIGTERM)
flushes and fsyncs.

### Format

One JSON object per line, newline-terminated, UTF-8, no enclosing array:

```json
{"id":8123,"ts":1787346189451,"service":"ssh","type":"auth_attempt","remoteIp":"185.220.101.1","remotePort":44122,"localPort":22,"username":"root","password":"123456","sessionId":"a1b2c3d4","country":"Germany","countryCode":"DE","org":"Zwiebelfreunde e.V.","details":{"method":"password"}}
```

Field notes:

- `ts` is Unix **milliseconds**, UTC.
- `id` is a per-process counter, restored from the replayed tail on boot —
  unique within a run, not globally.
- `country` / `countryCode` / `org` appear only if GeoIP had the answer at
  log time. Events logged before a lookup landed keep them empty on disk;
  the API fills them in on the way out to a client.
- `details` is free-form per protocol, and capped — see below.

It is `jq`-friendly by design:

```bash
# top credentials, all history
jq -r 'select(.password) | "\(.username):\(.password)"' data/events.ndjson |
  sort | uniq -c | sort -rn | head

# every command captured by the fake SSH shell today
jq -r 'select(.type=="command") | "\(.ts) \(.remoteIp) \(.command)"' data/events.ndjson

# both generations, oldest first
cat data/events.ndjson.1 data/events.ndjson | jq -c 'select(.service=="smtp")'
```

## What is kept in memory

| Structure | Bound | Cost |
|---|---|---|
| Event ring (`[]Event`) | `storage.maxLogRows` (25,000) | ~1–3.5 KB per event |
| Session table (`map[string]*Session`) | `storage.maxSessions` (20,000) | ~260 bytes each |
| Stats aggregate | one cached copy, `storage.statsCacheMs` (3 s) | negligible |
| GeoIP cache | 200,000 entries | ~150 bytes each |

The ring is the working set for the dashboard's Live and History tabs and
for every aggregate. Older events remain in `events.ndjson`, which is why
lowering `maxLogRows` costs memory-resident history, not history.

## Limits and what they cost

```jsonc
"storage": {
  "maxLogRows":     25000,        // events in memory — the main RAM dial
  "maxSessions":    20000,        // session table rows
  "maxDetailBytes": 2048,         // ceiling for an event's whole details map
  "maxLogFileMb":   128,          // rotate past this; -1 never rotates
  "statsCacheMs":   3000,         // serve the aggregate from cache this long
  "stdoutEvents":   "important"   // journal volume: important | all | none
}
```

- `maxDetailBytes` applies **at log time**, so it decides what is written
  to disk as well as what is held in memory. HTTP bodies are read at most
  16 KB before this cap applies. Truncated values carry a
  `…[truncated]` marker.
- Session rows are evicted **oldest-closed-first**; active sessions are
  kept. UDP groups a source into one session per 2-minute window instead
  of one per datagram.
- Rotation keeps exactly one previous generation, so disk use is bounded by
  `2 × maxLogFileMb` (plus the geo cache and keys).

Measured footprint and sizing profiles for 512 MB / 1 GB / 4 GB hosts:
[go-honeypot/README.md](../go-honeypot/README.md#what-it-stores-where-and-for-how-long).

## Boot: what gets restored

On start the daemon replays the tail of `events.ndjson` so a dashboard
connecting after a restart still sees history:

1. If the file is larger than the ring could hold, **seek** to
   `min(maxLogRows × 4 KB, maxLogFileMb)` from the end and discard the
   first (partial) line. A multi-gigabyte log costs a seek, not a read.
2. Parse line by line, keeping the last `maxLogRows` events. Unparseable
   lines are skipped.
3. Rebuild session rows from the replayed events, and mark every one
   `closed` — nothing from a previous process is really live.
4. `data/events.ndjson.1` is **not** replayed. It exists for `jq` and
   offline analysis.

Counters that describe "this run" (uptime, first hit after start, events
this run) deliberately exclude replayed events: replay does not go through
`Log`, which is what separates the two.

## The journal

Events are also mirrored to stdout, which under systemd means the journal.
`storage.stdoutEvents` controls how much:

| Value | Behaviour |
|---|---|
| `important` (default) | credentials, commands, relay/proxy attempts, amplification attempts, errors, start/stop |
| `all` | one line per event — on a scanned host this is a real CPU and disk cost |
| `none` | nothing but the startup banner and daemon-level messages |

The journal is not the record of truth — `events.ndjson` is. Cap it:
`SystemMaxUse=200M` in `/etc/systemd/journald.conf`, or
`journalctl --vacuum-size=100M` to reclaim now.

## Operating on the files

**Back up** (the config and the keys are what matter; the event log is
usually replaceable):

```bash
sudo tar czf honeystack-backup.tgz \
  -C /opt/honeystack config.json data/ssh_host_ed25519_key
```

Keeping the SSH host key means attackers see the same fingerprint after a
rebuild. Add `data/dyndns.json` if you want to keep the same hostname. Do
**not** back up `auth.key` — it is regenerated per start.

`data/ip-history.json` is a plain array of `{ts, ip, previousIp, source,
hostname, update, httpStatus, first}` objects, newest last, capped at
`dyndns.maxHistory`. It is also what the daemon reads on boot to avoid
recording a spurious change after a restart.

**Shrink a log that already grew** (rotation only applies going forward):

```bash
sudo systemctl stop honeypot-go
sudo tail -c 100000000 /opt/honeystack/data/events.ndjson > /tmp/e.ndjson
sudo mv /tmp/e.ndjson /opt/honeystack/data/events.ndjson
sudo chown honeypot:honeypot /opt/honeystack/data/events.ndjson
sudo systemctl start honeypot-go
```

**Ship events elsewhere.** The log is append-only NDJSON, so the usual
tools work: `tail -F data/events.ndjson | your-shipper`, a Filebeat/Vector
file input, or `promtail`. Rotation renames rather than truncates, so a
shipper following the inode needs `follow_renames`-style handling — or
point it at the WebSocket API instead, which streams every event live.

**Move the install.** Stop the service, move the directory, update
`WorkingDirectory=` and `ExecStart=` in the unit, `daemon-reload`, start.
All storage paths are relative to that directory, so nothing else changes.

## Permissions

- `data/` is `0750` and owned by the service account (`honeypot` by
  default). The two secrets inside are `0600`.
- The daemon runs as an unprivileged user with only
  `CAP_NET_BIND_SERVICE`, plus `NoNewPrivileges`, `ProtectSystem=full`,
  `ProtectHome=true`, `PrivateTmp=true` and `ReadWritePaths=` limited to
  the install directory. It cannot write anywhere else.
- `config.json` is `0644` and owned by the service account, because the
  dashboard writes it.

## Everything an attacker can influence

Worth stating explicitly, since it decides how much a probe can cost you:

| Input | Bound |
|---|---|
| bytes read per connection | protocol-specific, ≤ 16 KB for HTTP bodies, `captureBytes` (8 KB) for generic TCP |
| detail stored per event | `maxDetailBytes` (2 KB) |
| events retained | `maxLogRows` |
| session rows created | `maxSessions`, and one per 2-minute window for UDP |
| disk written | `2 × maxLogFileMb` |
| connection lifetime | `idleTimeoutSec` (60 s) |
| reply size (UDP) | never larger than the request |
