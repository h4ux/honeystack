# Security policy

Honeystack is a honeypot: it is *designed* to look vulnerable to whoever
connects to its decoy ports. That makes the line between "working as
intended" and "a real vulnerability" unusual, so please read the scope
below before reporting.

## Supported versions

| Version | Supported |
|---|---|
| `nightly` release / `main` | ✅ fixes land here |
| Older tags and vendored copies | ❌ upgrade first (`scripts/update-server.sh`) |

There is one moving release train. If you are running a build older than
the current `nightly`, reproduce on the latest build before reporting.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Open a private report through GitHub — **Security → Advisories → Report a
vulnerability** on
<https://github.com/h4ux/honeystack/security/advisories/new>. That channel
is private to the maintainers, supports attachments and discussion, and
becomes the advisory if the report is confirmed.

Please include:

- affected component (control API, dashboard, a specific honeypot
  emulator, a deploy script) and the build (`honeypot --version`)
- what an attacker gains, and the minimum steps or packet capture to
  reproduce it
- your platform (OS, Go version if you built from source)

What to expect: acknowledgement within **3 working days**, an assessment
within **10 working days**, and a fix or a documented mitigation for
confirmed issues. We will credit you in the release notes unless you ask
us not to.

## In scope

These are real vulnerabilities — please report them:

- **Control API**: authentication bypass, auth-key leakage, token
  comparison weaknesses, CORS/origin handling that lets a third-party page
  drive the API, path traversal, unauthenticated writes to config.
- **Honeypot emulators**: anything that escapes the emulation — remote
  code execution on the host, writing outside the data directory, a panic
  that takes the whole daemon down (a handler panic is contained by
  design; a process-wide crash is not), unbounded memory or disk growth
  from a single connection.
- **Amplification and abuse**: any input that makes a UDP emulator reply
  with *more* bytes than it received, or that makes the daemon relay,
  forward, tunnel or deliver traffic on an attacker's behalf. The proxy,
  mail and VPN emulators must never forward anything.
- **Dashboard**: stored or reflected XSS (event fields are attacker
  controlled), prototype pollution, or anything that turns logged data
  into code execution in an operator's browser.
- **Deploy scripts**: command injection through arguments or downloaded
  content, TOCTOU on the binary swap, checksum verification that can be
  skipped silently, or an sshd edit that can lock an operator out without
  the fail-safe restoring the backup.
- **Supply chain**: a release asset that does not match its
  `SHA256SUMS`, or a workflow that could be made to publish one.

## Not in scope

These are the product working as designed:

- The honeypot accepts fake credentials, "grants" logins, or shows a fake
  shell — that is the point (`fakeAuth` controls it).
- Decoy ports are open and answer to anyone, and the deploy script offers
  to disable the host firewall.
- The fake shell "runs" commands: it never executes anything, it prints
  canned output.
- Attacker-supplied data appears verbatim in the dashboard, the PDF report
  and `events.ndjson` — it is escaped on render; report it if you find a
  path where it is not.
- The dashboard is unauthenticated *apart from* the auth key, and the key
  rotates on every daemon restart by design.
- Running the daemon as root, exposing the control API to the internet
  without TLS, or reusing credentials from a real host: see the hardening
  notes below.
- GeoIP lookups sending attacker IPs to a third-party provider — that is
  documented and switchable (`geoip.enabled: false`).

## Operating it safely

The honeypot invites attacks, so treat the host as compromised-by-design:

- Dedicated throwaway VPS. No real data, no shared credentials, no access
  to internal networks, no cloud metadata credentials worth stealing.
- Keep the real sshd on its moved port with key-only authentication.
- Bind the control API to loopback or a VPN interface, or put TLS plus an
  IP allowlist in front of it (`control.tlsCertFile` / `tlsKeyFile`).
- Treat the auth key like a password; it rotates on restart.
- Watch disk: `events.ndjson` grows with every probe
  (`storage.maxLogRows` caps memory, not the file).
- Check your provider's ToS — some forbid honeypot-style traffic — and
  your local law before recording connection data.

## Hardening the daemon itself

The systemd unit installed by `scripts/deploy-remote.sh` runs the daemon
as a dedicated unprivileged account with only `CAP_NET_BIND_SERVICE`,
`NoNewPrivileges=true`, `ProtectSystem=full`, `ProtectHome=true` and
`PrivateTmp=true`. If you install by hand, do the same rather than running
it as root.
