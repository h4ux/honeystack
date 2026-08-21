# Getting help

- **Deploying on a server** — [go-honeypot/INSTRUCTIONS.md](./go-honeypot/INSTRUCTIONS.md)
  covers the guided installer, updating, port conflicts, TLS, and the
  common failure modes.
- **What each service captures / config reference** — [go-honeypot/README.md](./go-honeypot/README.md).
- **The Node.js edition** — [README.md](./README.md) and [INSTRUCTIONS.md](./INSTRUCTIONS.md).

## Something is not working

Check these first — they cover most reports:

| Symptom | Likely cause |
|---|---|
| Dashboard will not connect | wrong auth key (it rotates on every daemon restart: `sudo cat <install-dir>/data/auth.key`), or the control port is not reachable |
| `ws://` blocked from an `https://` page | use the relay/proxy option in the connect dialog |
| A service shows an error in the Services tab | port already owned by a real daemon (`systemd-resolved` on 53, Postfix on 25) — the error text is shown per service |
| No countries next to IPs | `geoip.enabled` is false, or the lookups are still queued (rate-limited to 40/min by default) |
| Nothing is being logged | the firewall is still filtering the decoy ports, or a cloud security group is |

If that does not solve it, open a
[bug report](https://github.com/h4ux/honeystack/issues/new/choose) with
the `honeypot --version` line, the service involved, and what you sent.

**Security problems go through [SECURITY.md](./SECURITY.md), not issues.**
