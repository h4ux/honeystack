# Honeystack documentation

Reference docs for the Go daemon. Task-oriented guides live at the top
level of the repo; this folder explains how the thing is built.

| Document | What it covers |
|---|---|
| [architecture.md](./architecture.md) | Packages and their dependencies, startup sequence, the hot path from probe to event, listener lifecycle, goroutine and lock map, the control API, and the constraints the design is built around |
| [storage.md](./storage.md) | Every file the daemon writes, the pattern used for each (append-only, temp+rename, write-once), the NDJSON format, in-memory limits, what boot restores, and how to back up, shrink or ship the data |

## Where everything else is

| I want to… | Go to |
|---|---|
| Deploy on a server | [go-honeypot/INSTRUCTIONS.md](../go-honeypot/INSTRUCTIONS.md) — §0 is the one-command path |
| Update a running server | [INSTRUCTIONS.md §2b](../go-honeypot/INSTRUCTIONS.md), or the build chip in the dashboard |
| Understand a listener / config field | [go-honeypot/README.md](../go-honeypot/README.md) — per-service tables and every config key |
| Size it for my VPS, or fix RAM/CPU use | [go-honeypot/README.md](../go-honeypot/README.md#what-it-stores-where-and-for-how-long), and [INSTRUCTIONS.md §2e](../go-honeypot/INSTRUCTIONS.md) when it is already unhappy |
| Add a protocol | [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-honeypot-service) |
| Report a vulnerability | [SECURITY.md](../SECURITY.md) — privately, and note the scope section |
| Run the Node.js edition instead | [README.md](../README.md) |

## The shape of it, in one paragraph

One static Go binary opens 41 decoy ports and an authenticated control
port. Every probe becomes an `Event`, which lands in a bounded in-memory
ring, is appended to `data/events.ndjson`, and is streamed to any
connected dashboard. The dashboard is a static page — it can be hosted
anywhere and connects back over WebSocket with a key the daemon rotates on
every start. Nothing is executed, nothing is forwarded, and every buffer,
table and file has a ceiling, because attacker input decides how much work
happens.
