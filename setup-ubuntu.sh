#!/usr/bin/env bash
#
# setup-ubuntu.sh
#
# Prepares an Ubuntu server to run the honeypot:
#   * Moves the real SSH daemon from port 22 to a safe port (default 1980)
#     BEFORE any firewall changes are made — with a fail-safe restore.
#   * Installs Node.js LTS if missing.
#   * Installs project dependencies.
#   * Opens the firewall on all honeypot ports (default: honeypot config).
#   * Grants Node the CAP_NET_BIND_SERVICE capability so it can bind
#     to privileged ports (<1024) without running as root.
#   * Optionally installs a systemd service to run the honeypot on boot.
#
# Usage (run as root, e.g. via sudo):
#
#   sudo bash setup-ubuntu.sh
#
# Environment overrides (all optional):
#
#   REAL_SSH_PORT=1980           Port the real sshd will listen on
#   DASHBOARD_PORT=8080          Port for the honeypot dashboard
#   ADMIN_USER=$SUDO_USER        Account allowed to log in via SSH (added
#                                to AllowUsers so you don't lock yourself out)
#   INSTALL_SERVICE=1            Install a systemd service (0 to skip)
#   OPEN_FIREWALL=1              Configure ufw (0 to skip)
#   NODE_MAJOR=20                Node.js major version to install if missing
#   HONEYPOT_DIR=$(pwd)          Directory containing package.json
#
# The script is idempotent; you can re-run it safely.

set -euo pipefail

# --------- config ---------
REAL_SSH_PORT="${REAL_SSH_PORT:-1980}"
DASHBOARD_PORT="${DASHBOARD_PORT:-8080}"
ADMIN_USER="${ADMIN_USER:-${SUDO_USER:-}}"
INSTALL_SERVICE="${INSTALL_SERVICE:-1}"
OPEN_FIREWALL="${OPEN_FIREWALL:-1}"
NODE_MAJOR="${NODE_MAJOR:-20}"
HONEYPOT_DIR="${HONEYPOT_DIR:-$(pwd)}"

# --------- helpers ---------
log()  { printf '\033[1;34m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root. Try: sudo bash $0"
  fi
}

require_ubuntu() {
  if ! grep -qiE 'ubuntu|debian' /etc/os-release 2>/dev/null; then
    warn "This script targets Ubuntu/Debian; continuing anyway."
  fi
}

# --------- steps ---------

configure_real_sshd() {
  log "Moving real sshd to port $REAL_SSH_PORT (from 22)"

  local sshd_config="/etc/ssh/sshd_config"
  [[ -f "$sshd_config" ]] || die "$sshd_config not found; is openssh-server installed?"

  local ts backup
  ts=$(date +%Y%m%d-%H%M%S)
  backup="${sshd_config}.honeypot-backup.${ts}"
  cp -a "$sshd_config" "$backup"
  log "Backed up sshd_config to $backup"

  # Remove all Port lines, replace with a single Port <REAL_SSH_PORT>.
  # Also ensure ListenAddress lines don't pin us to :22 explicitly.
  awk -v port="$REAL_SSH_PORT" '
    BEGIN { added=0 }
    /^[[:space:]]*Port[[:space:]]+/ {
      if (!added) { print "Port " port; added=1 }
      next
    }
    { print }
    END { if (!added) print "Port " port }
  ' "$sshd_config" > "${sshd_config}.new"
  mv "${sshd_config}.new" "$sshd_config"
  chmod 0644 "$sshd_config"

  # Ensure ListenAddress lines with :22 are neutralised
  sed -ri "s/^([[:space:]]*ListenAddress[[:space:]]+[^:[:space:]]+):22\b/\1:${REAL_SSH_PORT}/" "$sshd_config"

  if [[ -n "$ADMIN_USER" ]] && id "$ADMIN_USER" &>/dev/null; then
    if ! grep -qE "^AllowUsers.*\b${ADMIN_USER}\b" "$sshd_config"; then
      log "Ensuring AllowUsers contains ${ADMIN_USER} so you don't get locked out"
      if grep -qE '^AllowUsers' "$sshd_config"; then
        sed -ri "s/^AllowUsers(.*)/AllowUsers\1 ${ADMIN_USER}/" "$sshd_config"
      else
        printf '\n# added by honeypot setup-ubuntu.sh\nAllowUsers %s\n' "$ADMIN_USER" >> "$sshd_config"
      fi
    fi
  fi

  # Validate before restarting so we don't brick sshd.
  if ! sshd -t; then
    warn "sshd config validation failed; restoring backup."
    cp -a "$backup" "$sshd_config"
    die "Aborted — original sshd_config restored."
  fi

  # If systemd has a socket unit pinning port 22, disable it.
  if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.socket'; then
    log "Disabling ssh.socket (it hardcodes port 22)"
    systemctl disable --now ssh.socket 2>/dev/null || true
  fi
  if systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.socket'; then
    log "Disabling sshd.socket"
    systemctl disable --now sshd.socket 2>/dev/null || true
  fi

  local unit
  if systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then unit=sshd
  else unit=ssh
  fi
  systemctl enable --now "$unit" || true
  systemctl restart "$unit"

  if ss -tlnp 2>/dev/null | grep -qE ":${REAL_SSH_PORT}\b"; then
    log "sshd is now listening on ${REAL_SSH_PORT}"
  else
    warn "sshd does not appear to be listening on ${REAL_SSH_PORT}."
    warn "Check: systemctl status ${unit} && journalctl -u ${unit} -n 100"
  fi
}

install_node() {
  if command -v node >/dev/null 2>&1; then
    local v; v=$(node -v | sed 's/^v//; s/\..*//')
    if [[ "$v" -ge 18 ]]; then log "Node.js $(node -v) already installed"; return; fi
  fi
  log "Installing Node.js ${NODE_MAJOR}.x from NodeSource"
  apt-get update -y
  apt-get install -y curl ca-certificates gnupg build-essential
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -
  apt-get install -y nodejs
}

install_deps() {
  log "Installing npm dependencies in $HONEYPOT_DIR"
  (cd "$HONEYPOT_DIR" && npm install --omit=dev)
  # Allow Node to bind ports <1024 without root
  local node_bin; node_bin=$(readlink -f "$(command -v node)")
  if command -v setcap >/dev/null 2>&1; then
    log "Granting CAP_NET_BIND_SERVICE to $node_bin"
    setcap 'cap_net_bind_service=+ep' "$node_bin" || warn "setcap failed (non-fatal)"
  else
    apt-get install -y libcap2-bin
    setcap 'cap_net_bind_service=+ep' "$node_bin" || warn "setcap failed (non-fatal)"
  fi
}

configure_firewall() {
  if [[ "$OPEN_FIREWALL" != "1" ]]; then log "Skipping firewall configuration"; return; fi
  log "Configuring ufw firewall"
  apt-get install -y ufw >/dev/null 2>&1 || true

  # Extract honeypot ports from config
  local cfg="${HONEYPOT_DIR}/config.json"
  [[ -f "$cfg" ]] || cfg="${HONEYPOT_DIR}/config.default.json"

  local ports=(22 23 21 80 3389 3306 5900 445 6379)
  if command -v node >/dev/null 2>&1 && [[ -f "$cfg" ]]; then
    mapfile -t ports < <(node -e "
      const c=require('$cfg');
      const p=new Set();
      for (const s of Object.values(c.services||{})) if (s && s.port) p.add(s.port);
      for (const x of p) console.log(x);
    " 2>/dev/null || printf '22\n23\n21\n80\n3389\n3306\n5900\n445\n6379\n')
  fi

  ufw --force reset >/dev/null
  ufw default deny incoming
  ufw default allow outgoing
  # Real sshd first — critical so you don't lock yourself out
  ufw allow "${REAL_SSH_PORT}/tcp" comment 'real ssh'
  ufw allow "${DASHBOARD_PORT}/tcp" comment 'honeypot dashboard'
  for p in "${ports[@]}"; do
    ufw allow "${p}/tcp" comment 'honeypot'
  done
  ufw --force enable
  log "ufw enabled. Status:"
  ufw status verbose | sed 's/^/    /'
}

install_systemd_service() {
  if [[ "$INSTALL_SERVICE" != "1" ]]; then log "Skipping systemd install"; return; fi
  local user="${ADMIN_USER:-root}"
  local node_bin; node_bin=$(readlink -f "$(command -v node)")
  local unit=/etc/systemd/system/honeypot.service
  log "Writing $unit (runs as $user)"

  chown -R "$user":"$user" "$HONEYPOT_DIR" || true

  cat > "$unit" <<EOF
[Unit]
Description=Node.js honeypot suite
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$user
Group=$user
WorkingDirectory=$HONEYPOT_DIR
Environment=NODE_ENV=production
ExecStart=$node_bin $HONEYPOT_DIR/src/index.js
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=false
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now honeypot.service
  systemctl --no-pager --lines=15 status honeypot.service || true
}

print_summary() {
  echo
  log "Setup complete."
  echo "  * Real SSH:        port ${REAL_SSH_PORT}  (ssh -p ${REAL_SSH_PORT} ${ADMIN_USER:-user}@<host>)"
  echo "  * Dashboard:       http://<host>:${DASHBOARD_PORT}  (default admin/changeme — CHANGE THIS)"
  echo "  * Config file:     ${HONEYPOT_DIR}/config.json"
  echo "  * Database:        ${HONEYPOT_DIR}/data/honeypot.db"
  echo
  echo "Next steps:"
  echo "  1) Log out and reconnect on the new SSH port:  ssh -p ${REAL_SSH_PORT} ${ADMIN_USER:-user}@<host>"
  echo "  2) Change dashboard credentials in config.json (services -> dashboard)."
  echo "  3) Confirm all honeypot ports are reachable from outside."
  if [[ "$INSTALL_SERVICE" == "1" ]]; then
    echo "  4) journalctl -u honeypot -f     # tail live logs"
  fi
}

# --------- main ---------
require_root
require_ubuntu
configure_real_sshd
install_node
install_deps
configure_firewall
install_systemd_service
print_summary
