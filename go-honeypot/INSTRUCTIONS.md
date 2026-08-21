# Deploying the Go honeypot on Ubuntu

Everything below assumes a fresh Ubuntu 22.04 / 24.04 host. The Go
version is a **single static binary** (no Node runtime needed on the
server); the webapp runs on your workstation and connects over the
network with an auth key printed at startup.

> ⚠️ Before you begin: the setup script **moves your real SSH daemon
> off port 22** to `1980` so port 22 can be used by the honeypot. Keep
> a second SSH session open while you run it in case anything goes
> wrong.

## 1. Copy the project to the server

```bash
tar --exclude=server/data --exclude='server/*.exe' -czf go-honeypot.tgz -C /path/to/go-honeypot .
scp go-honeypot.tgz user@server:/opt/
ssh user@server
sudo mkdir -p /opt/go-honeypot
sudo tar -xzf /opt/go-honeypot.tgz -C /opt/go-honeypot
```

## 2. Run the setup script

```bash
cd /opt/go-honeypot
sudo bash setup-ubuntu.sh
```

To download the CI-built Linux binary instead of compiling on the
server (after the first successful push to `main`):

```bash
sudo GITHUB_REPO=owner/name USE_RELEASE=1 bash setup-ubuntu.sh
```

What it does:

1. Backs up `/etc/ssh/sshd_config` and sets `Port 1980` (validates with
   `sshd -t` before restart, restores backup on failure).
2. Adds `AllowUsers <you>` so you don't lock yourself out.
3. Installs Go via `apt` if missing.
4. Builds `server/` into `/usr/local/bin/honeypot`.
5. `setcap cap_net_bind_service=+ep` on the binary so it can bind
   ports <1024 without running as root.
6. Configures `ufw`: default-deny, then allows:
   - `1980/tcp` (real ssh)
   - `9090/tcp` (control API)
   - every port defined in `server/config.json` (or defaults).
7. Installs `honeypot-go.service` (systemd) and starts it.
8. Prints the auth key from `server/data/auth.key`.

Env overrides (set before the command):

```bash
sudo REAL_SSH_PORT=2222 CONTROL_PORT=9443 ADMIN_USER=ubuntu bash setup-ubuntu.sh
```

## 3. Reconnect on the new SSH port

```bash
ssh -p 1980 ubuntu@your-server
```

Only close the old session once you're sure the new one works.

## 4. Grab the auth key and connect the webapp

On the server:

```bash
cat /opt/go-honeypot/server/data/auth.key
# or
sudo journalctl -u honeypot-go -n 50 | grep 'auth key'
```

On your workstation:

```bash
cd /path/to/go-honeypot/webapp
node serve.js               # http://127.0.0.1:5173
```

Open the URL. Fill in:

- **Host / IP:** your server's address
- **Port:** `9090` (or whatever `CONTROL_PORT` you used)
- **Auth key:** the hex string from the server

The dashboard has the same tabs as the Node.js version: Live, SSH
Sessions, Services, Config, Stats.

## 5. Running without the systemd service

If you skipped systemd install (`INSTALL_SERVICE=0`):

```bash
cd /opt/go-honeypot/server
sudo /usr/local/bin/honeypot --config config.json
```

Or with `nohup`:

```bash
sudo nohup /usr/local/bin/honeypot --config /opt/go-honeypot/server/config.json \
   > /var/log/honeypot.log 2>&1 &
```

## 6. TLS

The control API is plain WebSocket (`ws://`). To use `wss://`:

1. Put the API behind nginx/caddy on port 443 with a proper certificate.
2. In `nginx`, proxy `/api` to `127.0.0.1:9090` with WebSocket upgrade:

   ```nginx
   location /api {
     proxy_pass http://127.0.0.1:9090/api;
     proxy_http_version 1.1;
     proxy_set_header Upgrade $http_upgrade;
     proxy_set_header Connection "Upgrade";
     proxy_set_header Host $host;
   }
   ```

3. Set `control.host` to `127.0.0.1` in `config.json` so the daemon only
   binds to loopback.
4. In the webapp check **"use wss://"** and enter `443` (or your TLS
   port).

## 7. Regenerating the auth key

Restart the service:

```bash
sudo systemctl restart honeypot-go
sudo cat /opt/go-honeypot/server/data/auth.key
```

Every start generates a new 32-byte random key.

## 8. Common issues

**`listen tcp :22: bind: permission denied`**
The binary is missing `cap_net_bind_service`. Re-apply:

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/honeypot
```

The systemd unit already sets `AmbientCapabilities=CAP_NET_BIND_SERVICE`.

**`bind: address already in use` on :22**
Another sshd is still holding port 22. Check with `sudo ss -tlnp | grep :22`.
Verify the move worked and, if needed, `sudo systemctl restart ssh`.

**WebSocket returns 401**
The token in the URL doesn't match the key in `data/auth.key`.

**Restoring the original sshd_config**

```bash
sudo ls /etc/ssh/sshd_config.honeypot-backup.*
sudo cp /etc/ssh/sshd_config.honeypot-backup.<timestamp> /etc/ssh/sshd_config
sudo systemctl restart ssh
```

**Tailing live activity**

```bash
sudo journalctl -u honeypot-go -f
# or read the raw log directly
sudo tail -f /opt/go-honeypot/server/data/events.ndjson | jq
```

## 9. Legal / operational

Some VPS providers forbid honeypot-style traffic. Check your TOS. Never
run this on a machine holding real user data or connected to internal
networks.
