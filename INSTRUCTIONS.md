# Honeypot — Ubuntu deployment guide

Everything the app needs to run on a fresh Ubuntu 22.04 (or 24.04) VPS.

> ⚠️ **Very important:** the setup script will **move your real SSH daemon
> off port 22** to a safe port (default `1980`) so port 22 can be used by
> the fake SSH honeypot. Read the "Before you begin" section below and
> keep a **second SSH session open** while running it, so you can recover
> if anything goes wrong.

---

## 1. Before you begin

You need:

- A Ubuntu server you don't mind exposing to the internet.
- Root access (via `sudo`).
- A second SSH session already connected to the server — leave it open
  during setup. If the config move breaks anything you can undo it there.
- (Recommended) a non-root sudo user, e.g. `ubuntu`. The setup script
  will add that user to `AllowUsers` in `sshd_config`, which greatly
  reduces the chance of locking yourself out.

Everything in this repo is safe to run on a throwaway VPS. **Do not run
a honeypot on a production machine.** Everything you expose here is
designed to attract attackers.

---

## 2. Copy the project to the server

From your workstation:

```bash
# create a tarball (skip node_modules and any local database)
tar --exclude=node_modules --exclude=data -czf honeypot.tgz -C /path/to/honeypot .

scp honeypot.tgz user@server:/opt/
ssh user@server
sudo mkdir -p /opt/honeypot
sudo tar -xzf /opt/honeypot.tgz -C /opt/honeypot
```

Or if the project is already in a git repo:

```bash
sudo apt-get update && sudo apt-get install -y git
sudo git clone <your-repo-url> /opt/honeypot
```

---

## 3. Run the setup script

```bash
cd /opt/honeypot
sudo bash setup-ubuntu.sh
```

What it does:

1. Backs up `/etc/ssh/sshd_config` (adds `.honeypot-backup.<timestamp>`).
2. Sets `Port 1980` in `sshd_config`, adds `AllowUsers <you>`, disables
   `ssh.socket` if present, runs `sshd -t` to validate, and restarts
   sshd. If validation fails, the backup is restored automatically.
3. Installs Node.js 20 (via NodeSource) if it's not already present.
4. Runs `npm install --omit=dev` in the project directory.
5. Grants the `node` binary `CAP_NET_BIND_SERVICE` so it can bind to
   ports below 1024 without running as root.
6. Configures `ufw`:
   - default deny incoming, default allow outgoing;
   - allow `1980/tcp` (real SSH), `8080/tcp` (dashboard);
   - allow every port listed in `config.json` (or `config.default.json`).
7. Installs a `honeypot.service` systemd unit and starts it.

Overrides (all optional, set before the command):

```bash
sudo REAL_SSH_PORT=2222 DASHBOARD_PORT=9000 ADMIN_USER=ubuntu bash setup-ubuntu.sh
```

Available env vars: `REAL_SSH_PORT`, `DASHBOARD_PORT`, `ADMIN_USER`,
`INSTALL_SERVICE` (0/1), `OPEN_FIREWALL` (0/1), `NODE_MAJOR`,
`HONEYPOT_DIR`.

---

## 4. Reconnect on the new SSH port

**Before closing your existing SSH session**, open a new terminal and
verify you can still get in:

```bash
ssh -p 1980 ubuntu@your-server
```

Only close the old session once the new one works.

---

## 5. Open the dashboard

Point your browser at:

```
http://your-server:8080
```

Default credentials: `admin` / `changeme`.

Change them immediately — edit `/opt/honeypot/config.json` and update:

```jsonc
"dashboard": {
  "host": "0.0.0.0",
  "port": 8080,
  "username": "admin",
  "password": "CHANGE-ME-TO-A-LONG-RANDOM-STRING",
  "bindLoopbackOnly": false
}
```

Then restart:

```bash
sudo systemctl restart honeypot
```

For extra safety, put the dashboard behind a reverse proxy (nginx/caddy)
with TLS and IP allowlisting, and set `"bindLoopbackOnly": true` so the
dashboard is only reachable through the proxy.

---

## 6. Running without systemd

If you skipped systemd install (`INSTALL_SERVICE=0`), start it manually:

```bash
cd /opt/honeypot
sudo -E node src/index.js
```

Or in the background with `nohup`:

```bash
nohup sudo -E node src/index.js > /var/log/honeypot.log 2>&1 &
```

---

## 7. Common issues

**"listen EACCES: permission denied 0.0.0.0:22"**
Node doesn't have permission to bind to privileged ports. Re-run:

```bash
sudo setcap 'cap_net_bind_service=+ep' "$(readlink -f "$(command -v node)")"
```

The systemd unit already grants `AmbientCapabilities=CAP_NET_BIND_SERVICE`,
so this is only an issue when running manually as non-root.

**"listen EADDRINUSE 0.0.0.0:22"**
Another sshd is still bound to port 22. Check with:

```bash
sudo ss -tlnp | grep :22
```

Kill/disable it, or set that port to `enabled: false` in the config.

**Restoring the original sshd_config**
The setup script leaves a backup next to the file:

```bash
sudo ls /etc/ssh/sshd_config.honeypot-backup.*
sudo cp /etc/ssh/sshd_config.honeypot-backup.<timestamp> /etc/ssh/sshd_config
sudo systemctl restart ssh
```

**Tail live activity**

```bash
sudo journalctl -u honeypot -f
```

---

## 8. Legal / operational note

Running a honeypot exposes services on your IP that appear vulnerable.
Some hosting providers explicitly forbid honeypots or hacking-related
traffic. Check your provider's ToS. Never point real user data at this
host — the fake SSH shell is designed to look real to attackers, but it
records everything they type.
