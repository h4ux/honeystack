#!/usr/bin/env bash
#
# setup-ubuntu.sh — deploy the Go honeypot binary to an Ubuntu server.
#
# * Moves the real sshd off port 22 (default -> port 1980) BEFORE any
#   firewall changes, with a fail-safe restore if sshd -t fails.
# * Installs Go if missing, builds the binary, grants CAP_NET_BIND_SERVICE.
# * Opens ufw for the honeypot ports listed in config.default.json (or
#   config.json if it exists), plus the real sshd port and the control
#   API port.
# * Installs a systemd service that runs the binary on boot.
#
# Usage:
#   sudo bash setup-ubuntu.sh
#
# Environment overrides:
#   REAL_SSH_PORT=1980       Port the real sshd will move to.
#   CONTROL_PORT=9090        Port the WebSocket control API listens on.
#   ADMIN_USER=$SUDO_USER    User added to sshd AllowUsers.
#   INSTALL_SERVICE=1        Install a systemd service (0 to skip).
#   OPEN_FIREWALL=1          Configure ufw (0 to skip).
#   USE_RELEASE=0            If 1, download the CI binary via scripts/install.sh
#                            instead of compiling (needs GITHUB_REPO=owner/name).
#   HONEYPOT_DIR=$(pwd)      Root of the go-honeypot checkout.

set -euo pipefail

REAL_SSH_PORT="${REAL_SSH_PORT:-1980}"
CONTROL_PORT="${CONTROL_PORT:-9090}"
ADMIN_USER="${ADMIN_USER:-${SUDO_USER:-}}"
INSTALL_SERVICE="${INSTALL_SERVICE:-1}"
OPEN_FIREWALL="${OPEN_FIREWALL:-1}"
HONEYPOT_DIR="${HONEYPOT_DIR:-$(pwd)}"
SERVER_DIR=""
BIN_PATH="/usr/local/bin/honeypot"
# If 1, download the matching CI binary instead of compiling locally.
# Requires GITHUB_REPO=owner/name (or a git remote) and a published nightly release.
USE_RELEASE="${USE_RELEASE:-0}"

log()  { printf '\033[1;34m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

require_root() { [[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0"; }

configure_real_sshd() {
  log "Moving real sshd from port 22 to $REAL_SSH_PORT"
  local cfg="/etc/ssh/sshd_config"
  [[ -f "$cfg" ]] || die "$cfg missing (install openssh-server first)"
  local backup="${cfg}.honeypot-backup.$(date +%Y%m%d-%H%M%S)"
  cp -a "$cfg" "$backup"
  log "Backup: $backup"

  awk -v port="$REAL_SSH_PORT" '
    BEGIN { added=0 }
    /^[[:space:]]*Port[[:space:]]+/ { if (!added) { print "Port " port; added=1 } next }
    { print }
    END { if (!added) print "Port " port }
  ' "$cfg" > "${cfg}.new" && mv "${cfg}.new" "$cfg"
  chmod 0644 "$cfg"
  sed -ri "s/^([[:space:]]*ListenAddress[[:space:]]+[^:[:space:]]+):22\b/\1:${REAL_SSH_PORT}/" "$cfg"

  if [[ -n "$ADMIN_USER" ]] && id "$ADMIN_USER" &>/dev/null; then
    if ! grep -qE "^AllowUsers.*\b${ADMIN_USER}\b" "$cfg"; then
      log "Adding AllowUsers ${ADMIN_USER}"
      if grep -qE '^AllowUsers' "$cfg"; then
        sed -ri "s/^AllowUsers(.*)/AllowUsers\1 ${ADMIN_USER}/" "$cfg"
      else
        printf '\nAllowUsers %s\n' "$ADMIN_USER" >> "$cfg"
      fi
    fi
  fi

  if ! sshd -t; then
    warn "sshd -t failed, restoring backup"
    cp -a "$backup" "$cfg"
    die "aborted; sshd_config restored"
  fi

  systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.socket' && systemctl disable --now ssh.socket 2>/dev/null || true
  systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.socket' && systemctl disable --now sshd.socket 2>/dev/null || true

  local unit=ssh
  systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service' && unit=sshd
  systemctl enable --now "$unit" || true
  systemctl restart "$unit"

  if ss -tlnp 2>/dev/null | grep -qE ":${REAL_SSH_PORT}\b"; then
    log "sshd is listening on ${REAL_SSH_PORT}"
  else
    warn "sshd does not appear to be on ${REAL_SSH_PORT}: check journalctl -u ${unit}"
  fi
}

install_go() {
  if command -v go >/dev/null 2>&1; then
    log "Go already installed: $(go version)"
    return
  fi
  log "Installing Go via apt"
  apt-get update -y
  apt-get install -y golang-go build-essential
}

resolve_server_dir() {
  if [[ -f "$HONEYPOT_DIR/server/go.mod" ]]; then
    SERVER_DIR="$HONEYPOT_DIR/server"
  elif [[ -f "$HONEYPOT_DIR/go-honeypot/server/go.mod" ]]; then
    HONEYPOT_DIR="$HONEYPOT_DIR/go-honeypot"
    SERVER_DIR="$HONEYPOT_DIR/server"
  elif [[ -f "$HONEYPOT_DIR/go.mod" ]] && grep -qE '^module ' "$HONEYPOT_DIR/go.mod"; then
    SERVER_DIR="$HONEYPOT_DIR"
  else
    die "Could not find server/go.mod under $HONEYPOT_DIR (run this from the go-honeypot directory)"
  fi
}

build_binary() {
  if [[ "$USE_RELEASE" == "1" ]]; then
    log "Downloading pre-built binary via scripts/install.sh"
    apt-get install -y curl ca-certificates >/dev/null 2>&1 || true
    bash "$HONEYPOT_DIR/scripts/install.sh" --output "$BIN_PATH"
  else
    [[ -f "$SERVER_DIR/go.mod" ]] || die "Missing $SERVER_DIR/go.mod"
    [[ -d "$SERVER_DIR/internal" ]] || die "Missing $SERVER_DIR/internal — unpack the full zip, not just main.go"
    log "Building honeypot binary from $SERVER_DIR"
    # go.mod requires Go >= 1.25 (golang.org/x/crypto v0.52.0), which is
    # newer than the toolchain Ubuntu ships, so GOTOOLCHAIN stays on 'auto':
    # the distro Go downloads the matching toolchain on first build. If the
    # server has no outbound network, use USE_RELEASE=1 instead of compiling.
    (
      cd "$SERVER_DIR"
      export GO111MODULE=on
      export GOTOOLCHAIN=auto
      unset GOFLAGS || true
      if [[ -d vendor ]]; then
        go build -mod=vendor -o "$BIN_PATH" .
      else
        go build -o "$BIN_PATH" .
      fi
    )
  fi
  chmod 0755 "$BIN_PATH"
  if command -v setcap >/dev/null 2>&1; then
    setcap 'cap_net_bind_service=+ep' "$BIN_PATH" || warn "setcap failed (non-fatal)"
  else
    apt-get install -y libcap2-bin
    setcap 'cap_net_bind_service=+ep' "$BIN_PATH" || warn "setcap failed (non-fatal)"
  fi
}

collect_ports() {
  local cfg="$SERVER_DIR/config.json"
  [[ -f "$cfg" ]] || cfg="$SERVER_DIR/config.default.json"
  python3 - "$cfg" <<'PY'
import json, sys
with open(sys.argv[1]) as f: c = json.load(f)
for name, svc in (c.get("services") or {}).items():
    p = svc.get("port")
    if p: print(p)
PY
}

configure_firewall() {
  [[ "$OPEN_FIREWALL" == "1" ]] || { log "Skipping firewall"; return; }
  log "Configuring ufw"
  apt-get install -y ufw python3 >/dev/null 2>&1 || true
  local ports=(22 23 21 80 3389 3306 5900 445 6379)
  if command -v python3 >/dev/null 2>&1; then
    mapfile -t ports < <(collect_ports || true)
  fi

  ufw --force reset >/dev/null
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "${REAL_SSH_PORT}/tcp" comment 'real ssh'
  ufw allow "${CONTROL_PORT}/tcp"  comment 'honeypot control API'
  for p in "${ports[@]}"; do
    [[ -n "$p" ]] && ufw allow "${p}/tcp" comment 'honeypot'
  done
  ufw --force enable
  ufw status verbose | sed 's/^/    /'
}

install_systemd() {
  [[ "$INSTALL_SERVICE" == "1" ]] || { log "Skipping systemd"; return; }
  local user="${ADMIN_USER:-root}"
  local work_dir="$SERVER_DIR"
  install -d -o "$user" -g "$user" -m 0755 "$work_dir/data"

  cat > /etc/systemd/system/honeypot-go.service <<EOF
[Unit]
Description=Go honeypot daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$user
Group=$user
WorkingDirectory=$work_dir
ExecStart=$BIN_PATH --defaults $work_dir/config.default.json --config $work_dir/config.json
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
  systemctl enable --now honeypot-go.service
  systemctl --no-pager --lines=15 status honeypot-go.service || true
  log "Auth key (also stored at $work_dir/data/auth.key):"
  sleep 1
  cat "$work_dir/data/auth.key" 2>/dev/null || warn "auth key not yet written; check the service logs"
}

summary() {
  echo
  log "Done."
  echo "  * Real SSH   : port ${REAL_SSH_PORT}  (ssh -p ${REAL_SSH_PORT} ${ADMIN_USER:-user}@<host>)"
  echo "  * Control API: ws://<host>:${CONTROL_PORT}/api?token=<AUTH_KEY>"
  echo "  * Auth key   : ${SERVER_DIR}/data/auth.key"
  echo "  * Binary     : ${BIN_PATH}"
  echo
  echo "Next: run the webapp locally"
  echo "  cd webapp && node serve.js"
  echo "  open http://127.0.0.1:5173  →  Host <server-ip>  Port ${CONTROL_PORT}  Auth key <from above>"
}

require_root
resolve_server_dir
configure_real_sshd
if [[ "$USE_RELEASE" != "1" ]]; then
  install_go
fi
build_binary
configure_firewall
install_systemd
summary
