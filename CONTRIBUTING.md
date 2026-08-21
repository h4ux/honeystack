# Contributing to Honeystack

Thanks for helping. This repo holds two implementations of the same
honeypot — a Node.js one at the root and the Go one under
[`go-honeypot/`](./go-honeypot) — plus a static dashboard and the deploy
scripts. Most new work happens in the Go tree.

Before anything else: please read [SECURITY.md](./SECURITY.md) if you
found a vulnerability, and do **not** open a public issue for it.

## Ground rules

- A honeypot must never become a weapon. Emulators may *look* exploitable
  but must not execute commands, forward traffic, relay mail, tunnel
  connections, or answer a UDP probe with more bytes than it received.
- Nothing is executed on the host. Fake shells print canned output.
- Attacker input is untrusted everywhere: bound every read, cap every
  buffer, and escape it on render.
- Keep the daemon dependency-light (currently: `gliderlabs/ssh`,
  `gorilla/websocket`, `golang.org/x/crypto`) and the dashboard
  build-step-free — no bundler, no framework, no CDN.

## Getting set up

You need **Go 1.25+** (the `golang.org/x/crypto` floor) and Node 18+ only
for the tiny dashboard file server.

```bash
git clone https://github.com/h4ux/honeystack.git
cd honeystack/go-honeypot/server

# unprivileged ports so you do not need root; see config.default.json
cp config.default.json config.json
$EDITOR config.json          # e.g. ssh 2222, http 8081, control 9090

go run . --config config.json           # prints the auth key
```

In a second terminal:

```bash
cd go-honeypot/webapp
node serve.js                            # http://127.0.0.1:5173
```

The page prefills the auth key from `../server/data/auth.key`.

## Checks to run before opening a PR

```bash
cd go-honeypot/server
gofmt -l .                     # must print nothing (vendor/ excluded by CI)
go vet -mod=vendor ./...
go test -race -mod=vendor ./...
go build -mod=vendor ./...

# dashboard: no build step, but the syntax must be clean
cd ../webapp && for f in app.js charts.js icons.js pdf.js serve.js; do node --check "$f"; done

# scripts
bash -n go-honeypot/scripts/*.sh
```

CI (`.github/workflows/ci.yml`) runs the same things on every PR, plus a
cross-compile for all six release targets.

## Adding a honeypot service

This is the most common contribution, and the shape is fixed:

1. **Write the emulator** in `go-honeypot/server/internal/honeypots/`.
   Use `NewTCP(name, cfg, store, handler)` for TCP, or
   `NewUDPProto(name, cfg, store, handler)` for UDP. Both give you
   session bookkeeping, panic isolation and idle timeouts for free —
   look at `mail.go` (line protocol), `ldap.go` (binary/BER) or
   `netudp.go` (datagram) as templates.
2. **Log what an operator would want to pivot on**, using the existing
   event vocabulary: `connection`, `command`, `login_attempt`,
   `auth_success`, `payload`, `query`, `client_hello`,
   `amplification_attempt`. Put credentials in `Username`/`Password` (a
   community string or a digest response counts), the human-readable
   request in `Command`, and everything else in `Details`.
3. **Register it** in `registerHoneypots()` in
   `go-honeypot/server/main.go`.
4. **Add a default** to `go-honeypot/server/config.default.json` with the
   real-world port. Ship it disabled if it collides with something a
   normal Ubuntu host runs (see `dns` and port 53).
5. **Give it an icon**: add the service name to `MAP` in
   `go-honeypot/webapp/icons.js`, reusing an existing glyph or adding a
   new one. Glyphs are drawn here on purpose — please do not add vendor
   logos.
6. **Test the parser**, not the socket: table-driven tests over the wire
   format, as in `internal/honeypots/protocols_test.go`.
7. **Document it** in the service tables in
   [`go-honeypot/README.md`](./go-honeypot/README.md).

Checklist for a new emulator: does it refuse to forward/relay/execute? Is
every reply no larger than the request (for UDP)? Are all reads bounded?
Does it survive garbage input (fuzz it by hand with `nc`)?

## Dashboard changes

`webapp/` is plain HTML/CSS/JS loaded in this order: `pdf.js`,
`charts.js`, `icons.js`, `app.js`. Keep to that: no framework, no build,
no external requests (the page must work from `file://` and behind a
tunnel). Charts go through `charts.js` so they stay theme-able and
printable into the PDF report. Escape everything that came from an event.

## Commits and PRs

- Small, focused commits with a one-line summary in the imperative
  ("Add SMTP relay capture"), then a body explaining *why* when it is not
  obvious.
- Describe user-visible behaviour changes in the PR body, and say how you
  tested (`nc` transcript, screenshot, test output).
- Bug fixes should come with a regression test where the bug is testable.
- No CLA. Contributions are accepted under the repo's
  [MIT licence](./LICENSE).

## Reporting bugs and asking for features

Use the issue templates. For a bug, the daemon's `--version` line, the
service and the raw bytes involved make it reproducible in minutes;
without them it is usually guesswork. Questions and deployment help
belong in [SUPPORT.md](./SUPPORT.md).
