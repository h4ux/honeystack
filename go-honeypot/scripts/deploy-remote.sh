#!/usr/bin/env bash
#
# deploy-remote.sh — one-shot, step-by-step deployment of the Honeystack
# Go honeypot onto a fresh Ubuntu/Debian server.
#
# It is meant to be run *on the server*, including straight off the
# internet, and it asks before every change it makes:
#
#   1. pick and download the pre-built Go binary for this OS/CPU
#   2. move the real sshd off port 22 (default: 1980)
#   3. install + start the honeypot-go systemd service
#   4. disable the host firewall so the decoy ports are reachable
#
# Usage (interactive — recommended, prompts work because stdin is a tty):
#   curl -fsSL --show-error https://raw.githubusercontent.com/h4ux/honeystack/main/go-honeypot/scripts/deploy-remote.sh -o deploy-remote.sh
#   sudo bash deploy-remote.sh
#
# Usage (piped; prompts are read from /dev/tty):
#   curl -fsSL --show-error https://raw.githubusercontent.com/h4ux/honeystack/main/go-honeypot/scripts/deploy-remote.sh | sudo bash
#
# Usage (unattended, answers yes to everything):
#   curl -fsSL --show-error .../deploy-remote.sh | sudo bash -s -- --yes
#
# Options:
#   -y, --yes              assume yes for every question (unattended)
#       --repo OWNER/NAME  GitHub repo to fetch the binary from
#                          (default: h4ux/honeystack)
#       --tag TAG          release tag to download (default: nightly)
#       --binary PATH      install this local binary instead of downloading
#       --ssh-port N       port the real sshd moves to (default: 1980)
#       --control-port N   dashboard control API port (default: 9090)
#       --dir PATH         install root (default: /opt/honeystack)
#       --user NAME        system account that runs the daemon
#                          (default: honeypot)
#       --memory MB        daemon memory budget (default 192; sets
#                          GOMEMLIMIT, MemoryHigh and MemoryMax)
#       --skip-dyndns      do not set up any public name
#                          (IP changes are still tracked and logged)
#       --dyndns-user U    use an existing credential instead of creating one
#       --dyndns-pass P    (with --dyndns-host)
#       --dyndns-host H
#       --skip-binary      do not touch /usr/local/bin/honeypot
#       --skip-ssh         leave the real sshd where it is
#       --skip-service     do not install/start the systemd unit
#       --skip-firewall    leave the firewall exactly as it is
#       --keep-firewall    alias for --skip-firewall
#   -h, --help             this text
#
# Environment: GITHUB_TOKEN / GH_TOKEN are used (if set) for private repos.
#
# WARNING: this turns the machine into a deliberately exposed decoy. Run it
# on a throwaway host with no real data and no access to internal networks.

set -euo pipefail

REPO="${GITHUB_REPO:-${GITHUB_REPOSITORY:-h4ux/honeystack}}"
TAG="${TAG:-nightly}"
LOCAL_BINARY=""
SSH_PORT="${REAL_SSH_PORT:-1980}"
CONTROL_PORT="${CONTROL_PORT:-9090}"
INSTALL_DIR="${INSTALL_DIR:-/opt/honeystack}"
SVC_USER="${SVC_USER:-honeypot}"
# Memory ceilings for the service unit (MiB). Sized for a 1 GB VPS.
MEM_LIMIT_MB="${MEM_LIMIT_MB:-192}"
MEM_HIGH_MB="${MEM_HIGH_MB:-256}"
MEM_MAX_MB="${MEM_MAX_MB:-384}"
SERVICE_NAME="honeypot-go"
BIN_PATH="/usr/local/bin/honeypot"
ASSUME_YES=0
DO_BINARY=1
DO_SSH=1
DO_SERVICE=1
DO_FIREWALL=1
DO_DYNDNS=1
DYNDNS_USER=""
DYNDNS_PASS=""
DYNDNS_HOST=""
DYNDNS_PROVIDER=""
ADMIN_USER="${SUDO_USER:-}"

RAW_BASE="https://raw.githubusercontent.com/${REPO}/main/go-honeypot/server"

# ---------------------------------------------------------------- output
if [[ -t 1 ]]; then
  C_B=$'\033[1;34m'; C_G=$'\033[1;32m'; C_Y=$'\033[1;33m'; C_R=$'\033[1;31m'; C_D=$'\033[2m'; C_0=$'\033[0m'
else
  C_B=""; C_G=""; C_Y=""; C_R=""; C_D=""; C_0=""
fi
log()  { printf '%s[+]%s %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '%s[✓]%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_Y" "$C_0" "$*"; }
die()  { printf '%s[x]%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }
step() { printf '\n%s══ %s %s\n' "$C_B" "$*" "$C_0"; }
note() { printf '    %s%s%s\n' "$C_D" "$*" "$C_0"; }

# ------------------------------------------------------------- arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes)        ASSUME_YES=1; shift ;;
    --repo)          REPO="${2:?}"; RAW_BASE="https://raw.githubusercontent.com/${REPO}/main/go-honeypot/server"; shift 2 ;;
    --tag)           TAG="${2:?}"; shift 2 ;;
    --binary)        LOCAL_BINARY="${2:?}"; shift 2 ;;
    --ssh-port)      SSH_PORT="${2:?}"; shift 2 ;;
    --control-port)  CONTROL_PORT="${2:?}"; shift 2 ;;
    --dir)           INSTALL_DIR="${2:?}"; shift 2 ;;
    --user)          SVC_USER="${2:?}"; shift 2 ;;
    --memory)        MEM_LIMIT_MB="${2:?}"; MEM_HIGH_MB=$(( ${2} * 4 / 3 )); MEM_MAX_MB=$(( ${2} * 2 )); shift 2 ;;
    --skip-binary)   DO_BINARY=0; shift ;;
    --skip-ssh)      DO_SSH=0; shift ;;
    --skip-service)  DO_SERVICE=0; shift ;;
    --skip-firewall|--keep-firewall) DO_FIREWALL=0; shift ;;
    --skip-dyndns)   DO_DYNDNS=0; shift ;;
    --dyndns-user)   DYNDNS_USER="${2:?}"; shift 2 ;;
    --dyndns-pass)   DYNDNS_PASS="${2:?}"; shift 2 ;;
    --dyndns-host)   DYNDNS_HOST="${2:?}"; shift 2 ;;
    -h|--help)       sed -n '2,60p' "$0" | sed 's/^#\{1,\} \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

# --------------------------------------------------------------- prompts
# When this script is piped into bash, stdin is the script itself, so every
# question has to come from the controlling terminal instead.
TTY_IN=""
if [[ -r /dev/tty ]] && { : </dev/tty; } 2>/dev/null; then
  TTY_IN=/dev/tty
elif [[ -t 0 ]]; then
  TTY_IN=/dev/stdin
fi

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

ask() { # ask "question" [y|n]  -> 0 = yes, 1 = no
  local q="$1" def="${2:-y}" hint reply
  [[ "$def" == y ]] && hint="[Y/n]" || hint="[y/N]"
  if (( ASSUME_YES )); then
    printf '    %s %s %s(--yes)%s\n' "$q" "$hint" "$C_D" "$C_0"
    [[ "$def" == y ]] && return 0 || return 1
  fi
  [[ -n "$TTY_IN" ]] || die "no terminal to ask questions on. Re-run with --yes, or download the script and run 'sudo bash deploy-remote.sh'."
  while true; do
    printf '    %s %s ' "$q" "$hint" > /dev/tty 2>/dev/null || printf '    %s %s ' "$q" "$hint"
    IFS= read -r reply < "$TTY_IN" || reply=""
    reply="$(lower "${reply:-$def}")"
    case "$reply" in
      y|yes) return 0 ;;
      n|no)  return 1 ;;
      *)     printf '    please answer y or n\n' ;;
    esac
  done
}

askval() { # askval "question" "default" -> echoes the answer
  local q="$1" def="$2" reply
  if (( ASSUME_YES )) || [[ -z "$TTY_IN" ]]; then printf '%s' "$def"; return; fi
  printf '    %s [%s] ' "$q" "$def" > /dev/tty 2>/dev/null || printf '    %s [%s] ' "$q" "$def"
  IFS= read -r reply < "$TTY_IN" || reply=""
  printf '%s' "${reply:-$def}"
}

# -------------------------------------------------------------- preflight
[[ $EUID -eq 0 ]] || die "run as root:  sudo bash $0"
command -v systemctl >/dev/null 2>&1 || warn "systemd not found — the service step will be skipped"
for tool in curl uname; do
  command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done

# ---------- which binary does this machine need? ----------
detect_target() {
  local os arch s m
  s="$(lower "$(uname -s)")"
  m="$(lower "$(uname -m)")"
  case "$s" in
    linux*)  os=linux ;;
    darwin*) os=darwin ;;
    *) die "unsupported OS for this installer: $(uname -s)" ;;
  esac
  case "$m" in
    x86_64|amd64)  arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "no pre-built binary for architecture $(uname -m) — build from source instead (see go-honeypot/README.md)" ;;
  esac
  printf '%s %s' "$os" "$arch"
}
read -r TARGET_OS TARGET_ARCH <<<"$(detect_target)"
ASSET="honeypot-${TARGET_OS}-${TARGET_ARCH}"

DISTRO="$( (. /etc/os-release 2>/dev/null && printf '%s %s' "${NAME:-unknown}" "${VERSION_ID:-}") || printf 'unknown')"
CURRENT_SSH_PORTS="$(grep -Ehs '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2}' | paste -sd, - || true)"

cat <<BANNER

${C_B}┌──────────────────────────────────────────────────────────────┐
│  Honeystack — remote honeypot deployment                     │
└──────────────────────────────────────────────────────────────┘${C_0}

  host          : $(hostname) (${DISTRO})
  target binary : ${ASSET}   ${C_D}(from ${REPO} @ ${TAG})${C_0}
  install root  : ${INSTALL_DIR}
  service       : ${SERVICE_NAME}.service   (user: ${SVC_USER})
  memory budget : ${MEM_LIMIT_MB} MiB soft / ${MEM_HIGH_MB} MiB high / ${MEM_MAX_MB} MiB max
  real sshd     : ${CURRENT_SSH_PORTS:-22 (default)}  ->  ${SSH_PORT}
  control API   : 0.0.0.0:${CONTROL_PORT}  (dashboard connects here)

  This machine will be turned into a deliberately exposed decoy:
  fake SSH/Telnet/FTP/HTTP/DB services on the standard ports, and
  (if you agree below) no host firewall at all.

  ${C_Y}Only do this on a throwaway host with no real data.${C_0}
  Every step below asks first; answer n to skip it.

BANNER

ask "Continue with this deployment?" y || { echo "    nothing changed."; exit 0; }

if [[ -z "$ADMIN_USER" ]] && [[ -n "${LOGNAME:-}" ]] && [[ "${LOGNAME}" != "root" ]]; then
  ADMIN_USER="$LOGNAME"
fi

# ============================================================ step 1: bin
install_binary() {
  step "Step 1/5 — honeypot binary (${ASSET})"
  note "picks the release asset that matches this OS/CPU, verifies its"
  note "SHA-256 when the release publishes SHA256SUMS, and installs it to"
  note "${BIN_PATH}"

  if (( ! DO_BINARY )); then warn "skipped (--skip-binary)"; return; fi
  if [[ -x "$BIN_PATH" ]]; then
    note "already installed: $($BIN_PATH --help 2>&1 | head -n1 || true)"
    ask "Replace the existing ${BIN_PATH}?" y || { warn "keeping the current binary"; return; }
  fi
  ask "Download and install ${ASSET}?" y || { warn "skipped by request"; return; }

  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  if [[ -n "$LOCAL_BINARY" ]]; then
    [[ -f "$LOCAL_BINARY" ]] || die "no such file: $LOCAL_BINARY"
    cp "$LOCAL_BINARY" "$tmp/$ASSET"
    log "using local binary $LOCAL_BINARY"
  else
    local auth=() url=""
    local token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
    [[ -n "$token" ]] && auth=(-H "Authorization: Bearer ${token}")

    # Ask the API which asset matches, then fall back to the predictable
    # /releases/download/<tag>/<asset> path if the API is unreachable.
    log "looking up ${ASSET} in ${REPO} release '${TAG}'"
    url="$(curl -fsSL "${auth[@]}" \
             -H 'Accept: application/vnd.github+json' \
             "https://api.github.com/repos/${REPO}/releases/tags/${TAG}" 2>/dev/null \
           | tr ',' '\n' \
           | grep '"browser_download_url"' \
           | grep -F "/${ASSET}\"" \
           | sed 's/.*"\(https[^"]*\)".*/\1/' \
           | head -n1 || true)"
    if [[ -z "$url" ]]; then
      # Release tag not found: try whatever the newest release is.
      url="$(curl -fsSL "${auth[@]}" \
               -H 'Accept: application/vnd.github+json' \
               "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
             | tr ',' '\n' \
             | grep '"browser_download_url"' \
             | grep -F "/${ASSET}\"" \
             | sed 's/.*"\(https[^"]*\)".*/\1/' \
             | head -n1 || true)"
      [[ -n "$url" ]] && note "release '${TAG}' not found; using the latest release instead"
    fi
    if [[ -z "$url" ]]; then
      url="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
      note "GitHub API gave nothing usable; trying ${url}"
    fi
    log "downloading $url"
    if ! curl -fsSL "${auth[@]}" -o "$tmp/$ASSET" "$url"; then
      warn "could not download ${ASSET} from ${REPO}"
      note "the '${TAG}' release only exists after the go-honeypot workflow has"
      note "run on main. Options:"
      note "  * build it yourself:  cd go-honeypot/server && CGO_ENABLED=0 go build -o honeypot ."
      note "    then re-run this script with:  --binary /path/to/honeypot"
      note "  * or point at another repo/tag:  --repo owner/name --tag v1.2.3"
      die "no binary to install"
    fi

    # Optional integrity check against the release's SHA256SUMS.
    if curl -fsSL "${auth[@]}" -o "$tmp/SHA256SUMS" \
         "https://github.com/${REPO}/releases/download/${TAG}/SHA256SUMS" 2>/dev/null \
       && command -v sha256sum >/dev/null 2>&1; then
      if ( cd "$tmp" && grep -E "[[:space:]]\*?${ASSET}\$" SHA256SUMS | sha256sum -c - >/dev/null 2>&1 ); then
        ok "SHA-256 verified"
      else
        warn "checksum did NOT match the published SHA256SUMS"
        ask "Install it anyway?" n || die "aborted on checksum mismatch"
      fi
    else
      note "no SHA256SUMS published (or no sha256sum here) — skipping checksum"
    fi
  fi

  # Replacing a running binary needs the service stopped first.
  if systemctl is-active --quiet "${SERVICE_NAME}.service" 2>/dev/null; then
    log "stopping ${SERVICE_NAME} while the binary is replaced"
    systemctl stop "${SERVICE_NAME}.service"
  fi
  install -m 0755 "$tmp/$ASSET" "$BIN_PATH"
  if command -v setcap >/dev/null 2>&1; then
    setcap 'cap_net_bind_service=+ep' "$BIN_PATH" 2>/dev/null \
      || note "setcap failed (harmless: the service grants the capability itself)"
  fi
  ok "installed ${BIN_PATH}"

  # The daemon needs its defaults file next to a writable config.
  install -d -m 0755 "$INSTALL_DIR"
  if [[ ! -f "$INSTALL_DIR/config.default.json" ]]; then
    log "fetching config.default.json"
    curl -fsSL -o "$INSTALL_DIR/config.default.json" "${RAW_BASE}/config.default.json" \
      || die "could not fetch config.default.json from ${RAW_BASE}"
  fi
  if [[ ! -f "$INSTALL_DIR/config.json" ]]; then
    cp "$INSTALL_DIR/config.default.json" "$INSTALL_DIR/config.json"
    ok "created ${INSTALL_DIR}/config.json (edit it, or use the dashboard)"
  else
    note "keeping the existing ${INSTALL_DIR}/config.json"
  fi

  if [[ "$CONTROL_PORT" != "9090" ]] && command -v python3 >/dev/null 2>&1; then
    python3 - "$INSTALL_DIR/config.json" "$CONTROL_PORT" <<'PY'
import json, sys
path, port = sys.argv[1], int(sys.argv[2])
with open(path) as f:
    cfg = json.load(f)
cfg.setdefault("control", {})["port"] = port
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
PY
    ok "control API port set to ${CONTROL_PORT}"
  fi
}

# ============================================================ step 2: ssh
move_real_sshd() {
  step "Step 2/5 — move the real sshd to port ${SSH_PORT}"
  note "backs up /etc/ssh/sshd_config, rewrites Port, validates with"
  note "'sshd -t' (restoring the backup if it fails), then restarts sshd."
  note "Your current session stays open; new logins use port ${SSH_PORT}."

  if (( ! DO_SSH )); then warn "skipped (--skip-ssh)"; return; fi
  if ! ask "Move the real SSH daemon to port ${SSH_PORT}?" y; then
    warn "real sshd left alone — the SSH honeypot cannot use port 22 while sshd holds it"
    return
  fi
  local answer
  answer="$(askval "Which port should the real sshd use?" "$SSH_PORT")"
  [[ "$answer" =~ ^[0-9]+$ ]] && SSH_PORT="$answer"

  local cfg=/etc/ssh/sshd_config
  [[ -f "$cfg" ]] || die "$cfg not found (install openssh-server first)"
  local backup="${cfg}.honeystack-backup.$(date +%Y%m%d-%H%M%S)"
  cp -a "$cfg" "$backup"
  ok "backup: $backup"

  # Replace every Port line with one canonical entry.
  awk -v port="$SSH_PORT" '
    BEGIN { added = 0 }
    /^[[:space:]]*Port[[:space:]]+/ { if (!added) { print "Port " port; added = 1 } next }
    { print }
    END { if (!added) print "Port " port }
  ' "$cfg" > "${cfg}.honeystack-new" && mv "${cfg}.honeystack-new" "$cfg"
  chmod 0644 "$cfg"
  sed -ri "s/^([[:space:]]*ListenAddress[[:space:]]+[^:[:space:]]+):22\b/\1:${SSH_PORT}/" "$cfg"

  # Drop-ins in sshd_config.d can pin Port 22 and silently win.
  local dropin
  for dropin in /etc/ssh/sshd_config.d/*.conf; do
    [[ -e "$dropin" ]] || continue
    if grep -qE '^[[:space:]]*Port[[:space:]]+' "$dropin"; then
      cp -a "$dropin" "${dropin}.honeystack-backup"
      sed -ri "s/^([[:space:]]*Port[[:space:]]+).*/\1${SSH_PORT}/" "$dropin"
      ok "updated drop-in $dropin"
    fi
  done

  if [[ -n "$ADMIN_USER" ]] && id "$ADMIN_USER" &>/dev/null && grep -qE '^[[:space:]]*AllowUsers' "$cfg"; then
    if ! grep -qE "^[[:space:]]*AllowUsers.*\b${ADMIN_USER}\b" "$cfg"; then
      if ask "sshd has an AllowUsers list — add '${ADMIN_USER}' to it?" y; then
        sed -ri "s/^([[:space:]]*AllowUsers.*)/\1 ${ADMIN_USER}/" "$cfg"
      fi
    fi
  fi

  local sshd_bin
  sshd_bin="$(command -v sshd || echo /usr/sbin/sshd)"
  if ! "$sshd_bin" -t; then
    warn "sshd rejected the new config — restoring the backup"
    cp -a "$backup" "$cfg"
    die "aborted; /etc/ssh/sshd_config restored from $backup"
  fi
  ok "sshd config validates"

  # Modern Ubuntu socket-activates sshd, and the socket's port beats
  # sshd_config. Point the socket at the new port too.
  local unit=ssh
  systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service' && unit=sshd
  local socket=""
  systemctl list-unit-files 2>/dev/null | grep -qE '^(ssh|sshd)\.socket' && socket="$(systemctl list-unit-files 2>/dev/null | grep -oE '^(ssh|sshd)\.socket' | head -n1)"
  if [[ -n "$socket" ]] && systemctl is-enabled --quiet "$socket" 2>/dev/null; then
    log "this system socket-activates sshd ($socket); overriding its port"
    install -d -m 0755 "/etc/systemd/system/${socket}.d"
    cat > "/etc/systemd/system/${socket}.d/honeystack-port.conf" <<EOF
[Socket]
ListenStream=
ListenStream=${SSH_PORT}
EOF
    systemctl daemon-reload
    systemctl restart "$socket"
  fi

  log "restarting ${unit}"
  systemctl restart "$unit" || die "failed to restart ${unit} — check: journalctl -u ${unit} -n 50"

  sleep 1
  if command -v ss >/dev/null 2>&1 && ss -tln 2>/dev/null | grep -qE "[:.]${SSH_PORT}\b"; then
    ok "real sshd is listening on ${SSH_PORT}"
  else
    warn "could not confirm sshd on ${SSH_PORT} — check 'ss -tlnp' and 'journalctl -u ${unit}'"
  fi
  printf '\n    %sBefore you close this session, open a NEW terminal and run:%s\n' "$C_Y" "$C_0"
  local login_host
  login_host="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -z "$login_host" ]] && login_host="$(hostname)"
  printf '        ssh -p %s %s@%s\n\n' "$SSH_PORT" "${ADMIN_USER:-${USER:-root}}" "$login_host"
  ask "Did that work (or do you want to continue anyway)?" y || die "stopping here. Your old session is still open; fix SSH first (backup: $backup)."
}

# ==================================================== step 2b: public name
configure_dyndns() {
  step "Step 3/5 — a public name for this box"
  note "A honeypot on a dynamic IP loses its dashboard bookmark whenever the"
  note "address changes. Two options, both free and neither needs an account:"
  note "  sslip.io  — the name encodes the address (62-228-88-158.sslip.io)."
  note "              Always resolves, nothing to register, but the name"
  note "              changes when the address does."
  note "  xyz.frl   — a stable random name you keep. No signup either, but at"
  note "              the time of writing its names were not resolving."
  note "Either way the daemon tracks the address every 5 minutes and logs"
  note "every change in the dashboard."

  if (( ! DO_DYNDNS )); then warn "skipped (--skip-dyndns)"; return; fi

  local mode=""
  if [[ -n "$DYNDNS_USER" && -n "$DYNDNS_PASS" ]]; then
    mode="credentials"
    log "using the credentials passed on the command line"
  elif ask "Set up a public name for this host?" y; then
    if ask "Use sslip.io (nothing to register, name follows the IP)?" y; then
      mode="derived"
    elif ask "Try xyz.frl instead (stable name, may not resolve yet)?" n; then
      mode="xyzfrl"
    else
      mode="none"
    fi
  else
    mode="none"
  fi

  if [[ "$mode" == "none" ]]; then
    warn "no public name — the daemon still tracks and logs IP changes"
    DYNDNS_PROVIDER="sslip.io"
    set_dyndns_config "false" "sslip.io"
    return
  fi

  if [[ "$mode" == "derived" ]]; then
    DYNDNS_PROVIDER="sslip.io"
    set_dyndns_config "true" "sslip.io"
    local ip
    ip="$(curl -fsS -m 10 https://api.ipify.org 2>/dev/null || true)"
    if [[ -n "$ip" ]]; then
      DYNDNS_HOST="$(printf '%s' "$ip" | tr '.' '-').sslip.io"
      ok "public name: ${DYNDNS_HOST}"
      if command -v getent >/dev/null 2>&1 && getent hosts "$DYNDNS_HOST" >/dev/null 2>&1; then
        ok "${DYNDNS_HOST} resolves"
      else
        note "could not resolve it from here; the daemon will keep reporting it"
      fi
    else
      ok "sslip.io selected; the daemon derives the name once it sees its address"
    fi
    return
  fi

  if [[ "$mode" == "xyzfrl" ]]; then
    log "requesting a hostname from https://xyz.frl/generate"
    local json
    json="$(curl -fsSL --show-error -m 20 https://xyz.frl/generate 2>&1)" || {
      warn "could not reach xyz.frl: ${json}"
      note "falling back to sslip.io"
      DYNDNS_PROVIDER="sslip.io"
      set_dyndns_config "true" "sslip.io"
      return
    }
    DYNDNS_HOST="$(printf '%s' "$json" | sed -n 's/.*"hostname"[: ]*"\([^"]*\)".*/\1/p')"
    DYNDNS_USER="$(printf '%s' "$json" | sed -n 's/.*"username"[: ]*"\([^"]*\)".*/\1/p')"
    DYNDNS_PASS="$(printf '%s' "$json" | sed -n 's/.*"password"[: ]*"\([^"]*\)".*/\1/p')"
    if [[ -z "$DYNDNS_HOST" || -z "$DYNDNS_USER" || -z "$DYNDNS_PASS" ]]; then
      warn "unexpected response from xyz.frl: $(printf '%s' "$json" | head -c 120)"
      note "falling back to sslip.io"
      DYNDNS_PROVIDER="sslip.io"
      set_dyndns_config "true" "sslip.io"
      return
    fi
    ok "hostname: ${DYNDNS_HOST}"
  fi

  # A registered name (xyz.frl or credentials given on the command line).
  DYNDNS_PROVIDER="${DYNDNS_PROVIDER:-xyz.frl}"
  install -d -m 0750 "$INSTALL_DIR/data"
  cat > "$INSTALL_DIR/data/dyndns.json" <<EOF
{
  "hostname": "${DYNDNS_HOST}",
  "username": "${DYNDNS_USER}",
  "password": "${DYNDNS_PASS}"
}
EOF
  chmod 0600 "$INSTALL_DIR/data/dyndns.json"
  id "$SVC_USER" &>/dev/null && chown "$SVC_USER":"$SVC_USER" "$INSTALL_DIR/data/dyndns.json"
  ok "credentials stored in ${INSTALL_DIR}/data/dyndns.json (0600)"
  set_dyndns_config "true" "$DYNDNS_PROVIDER"

  local ip code
  ip="$(curl -fsS -m 10 https://api.ipify.org 2>/dev/null || true)"
  if [[ -n "$ip" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' -m 15 --user "${DYNDNS_USER}:${DYNDNS_PASS}" \
             "https://xyz.frl/nic/update?myip=${ip}" || true)"
    case "$code" in
      2*)  ok "first update accepted (HTTP ${code}) for ${ip}" ;;
      429) warn "provider rate-limited the first update — the daemon will retry" ;;
      *)   warn "first update returned HTTP ${code:-none}; the daemon will keep trying" ;;
    esac
    sleep 3
    if command -v getent >/dev/null 2>&1 && getent hosts "$DYNDNS_HOST" >/dev/null 2>&1; then
      ok "${DYNDNS_HOST} resolves"
    else
      warn "${DYNDNS_HOST} does not resolve yet"
      note "xyz.frl accepts updates but may not publish records. Switch to the"
      note "no-signup fallback any time:  dyndns.provider = \"sslip.io\" in"
      note "${INSTALL_DIR}/config.json (delete data/dyndns.json), or point"
      note "dyndns.updateUrl at a provider you control."
    fi
  fi
}

# set_dyndns_config <enabled> <provider>
set_dyndns_config() {
  local enabled="$1" provider="$2"
  if ! command -v python3 >/dev/null 2>&1 || [[ ! -f "$INSTALL_DIR/config.json" ]]; then
    warn "could not edit config.json — set dyndns.enabled/provider by hand"
    return
  fi
  python3 - "$INSTALL_DIR/config.json" "$enabled" "$provider" <<'PY'
import json, sys
path, enabled, provider = sys.argv[1], sys.argv[2] == "true", sys.argv[3]
with open(path) as f:
    cfg = json.load(f)
dyn = cfg.setdefault("dyndns", {})
dyn["enabled"] = enabled
dyn["provider"] = provider
dyn.setdefault("credentialsFile", "data/dyndns.json")
dyn.setdefault("intervalMinutes", 5)
dyn.setdefault("historyFile", "data/ip-history.json")
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
PY
  ok "dyndns: enabled=${enabled} provider=${provider} (refresh every 5 minutes)"
}

# ======================================================== step 3: service
install_service() {
  step "Step 4/5 — install and start ${SERVICE_NAME}.service"
  note "creates the '${SVC_USER}' system account, a data directory under"
  note "${INSTALL_DIR}/data, a systemd unit that grants only"
  note "CAP_NET_BIND_SERVICE, then enables and starts it."

  if (( ! DO_SERVICE )); then warn "skipped (--skip-service)"; return; fi
  command -v systemctl >/dev/null 2>&1 || { warn "no systemd here — skipping"; return; }
  [[ -x "$BIN_PATH" ]] || { warn "${BIN_PATH} is missing — run step 1 first"; return; }
  ask "Install the systemd service and start the honeypot now?" y || { warn "skipped by request"; return; }

  if ! id "$SVC_USER" &>/dev/null; then
    log "creating system user ${SVC_USER}"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
  fi
  install -d -m 0755 "$INSTALL_DIR"
  install -d -o "$SVC_USER" -g "$SVC_USER" -m 0750 "$INSTALL_DIR/data"
  [[ -f "$INSTALL_DIR/config.json" ]] || die "missing ${INSTALL_DIR}/config.json — run step 1 first"
  chown "$SVC_USER":"$SVC_USER" "$INSTALL_DIR/config.json"

  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Honeystack Go honeypot daemon
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BIN_PATH} --defaults ${INSTALL_DIR}/config.default.json --config ${INSTALL_DIR}/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
# Lets the daemon publish the "Status:" line that systemctl status prints,
# which is where the public URL and current IP show up.
NotifyAccess=main
# A soft limit makes Go collect harder instead of the kernel OOM-killing the
# daemon; MemoryHigh throttles it before MemoryMax would kill it. Raise both
# (and storage.maxLogRows) on a box with memory to spare.
Environment=GOMEMLIMIT=${MEM_LIMIT_MB}MiB
MemoryHigh=${MEM_HIGH_MB}M
MemoryMax=${MEM_MAX_MB}M
CPUWeight=50
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${INSTALL_DIR}

[Install]
WantedBy=multi-user.target
EOF
  # Never let a systemd hiccup abort the run: the remaining steps (and the
  # summary with the auth key) are still worth printing.
  systemctl daemon-reload || { warn "systemctl daemon-reload failed — is this really a systemd host?"; return; }
  systemctl enable "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
  systemctl restart "${SERVICE_NAME}.service" || warn "systemctl restart ${SERVICE_NAME} failed"
  sleep 2
  if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
    ok "${SERVICE_NAME} is running"
  else
    warn "${SERVICE_NAME} did not start:"
    systemctl --no-pager --lines=20 status "${SERVICE_NAME}.service" || true
    journalctl -u "${SERVICE_NAME}" -n 30 --no-pager || true
  fi
}

# ======================================================= step 4: firewall
firewall_ports() { # "<port>/<proto>" per enabled service, for the "open instead" path
  if command -v python3 >/dev/null 2>&1 && [[ -f "$INSTALL_DIR/config.json" ]]; then
    python3 - "$INSTALL_DIR/config.json" <<'PORTS'
import json, sys
with open(sys.argv[1]) as f:
    cfg = json.load(f)
for name, svc in (cfg.get("services") or {}).items():
    if svc.get("enabled") and svc.get("port"):
        proto = (svc.get("protocol") or "tcp").lower()
        if proto not in ("tcp", "udp"):
            proto = "tcp"
        print("%d/%s" % (svc["port"], proto))
PORTS
  fi
}

configure_firewall() {
  step "Step 5/5 — host firewall"
  note "A honeypot is only useful if the decoy ports answer, so the usual"
  note "choice is to disable the host firewall entirely. That leaves NOTHING"
  note "filtered on this machine — including the real sshd on ${SSH_PORT}."
  note "Cloud security groups / provider firewalls are separate: open them"
  note "yourself if the ports still look closed from the outside."

  if (( ! DO_FIREWALL )); then warn "skipped (--skip-firewall)"; return; fi

  local has_ufw=0 has_firewalld=0 has_nft=0 has_iptables=0
  command -v ufw >/dev/null 2>&1 && has_ufw=1
  command -v firewall-cmd >/dev/null 2>&1 && has_firewalld=1
  command -v nft >/dev/null 2>&1 && has_nft=1
  command -v iptables >/dev/null 2>&1 && has_iptables=1
  if (( has_ufw )); then note "ufw status: $(ufw status 2>/dev/null | head -n1)"; fi

  if ask "Disable the host firewall completely?" y; then
    if (( has_ufw )); then
      log "ufw disable"
      ufw --force disable || warn "ufw disable failed"
    fi
    if (( has_firewalld )); then
      log "stopping firewalld"
      systemctl disable --now firewalld 2>/dev/null || warn "could not disable firewalld"
    fi
    if (( has_iptables )); then
      log "flushing iptables (filter table, policies to ACCEPT)"
      for chain in INPUT FORWARD OUTPUT; do iptables -P "$chain" ACCEPT 2>/dev/null || true; done
      iptables -F 2>/dev/null || true
      iptables -X 2>/dev/null || true
      if command -v ip6tables >/dev/null 2>&1; then
        for chain in INPUT FORWARD OUTPUT; do ip6tables -P "$chain" ACCEPT 2>/dev/null || true; done
        ip6tables -F 2>/dev/null || true
      fi
    fi
    if (( has_nft )) && ask "Also flush the nftables ruleset?" y; then
      nft flush ruleset 2>/dev/null || warn "nft flush failed"
    fi
    ok "host firewall disabled — every port on this box is now reachable"
    warn "the real sshd on ${SSH_PORT} is unfiltered too; keep key-only auth on"
  else
    warn "firewall left enabled"
    if (( has_ufw )) && ask "Open the ports the honeypot needs in ufw instead?" y; then
      local ports p
      ports="$(firewall_ports)"
      ufw allow "${SSH_PORT}/tcp" comment 'real ssh' >/dev/null || true
      ufw allow "${CONTROL_PORT}/tcp" comment 'honeypot control API' >/dev/null || true
      # Entries are already "<port>/<proto>", so UDP decoys (DNS, SNMP, NTP,
      # IKE, WireGuard, ...) are opened as UDP instead of silently as TCP.
      for p in $ports; do
        [[ -n "$p" ]] && ufw allow "${p}" comment 'honeypot' >/dev/null || true
      done
      ufw --force enable >/dev/null || true
      ok "opened ${SSH_PORT}, ${CONTROL_PORT} and every enabled honeypot port"
      ufw status | sed 's/^/    /'
    fi
  fi
}

# ================================================================ summary
summary() {
  local key="" ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -z "$ip" ]] && ip="$(hostname)"
  if [[ -r "$INSTALL_DIR/data/auth.key" ]]; then
    key="$(cat "$INSTALL_DIR/data/auth.key")"
  fi

  step "Done"
  local dyn_line="not configured (IP changes are still tracked)"
  if [[ -n "$DYNDNS_HOST" ]]; then
    dyn_line="https://${DYNDNS_HOST}  (${DYNDNS_PROVIDER:-dyndns}, refreshed every 5 min)"
  elif [[ -n "$DYNDNS_PROVIDER" ]]; then
    dyn_line="${DYNDNS_PROVIDER} — name appears in 'systemctl status ${SERVICE_NAME}'"
  fi
  cat <<SUM
  real SSH      : ssh -p ${SSH_PORT} ${ADMIN_USER:-<user>}@${ip}
  public name   : ${dyn_line}
  service       : systemctl status ${SERVICE_NAME}   ·   journalctl -u ${SERVICE_NAME} -f
  binary        : ${BIN_PATH}
  config        : ${INSTALL_DIR}/config.json
  events        : ${INSTALL_DIR}/data/events.ndjson
  control API   : ws://${ip}:${CONTROL_PORT}/api
  auth key      : ${key:-<not written yet — check: journalctl -u ${SERVICE_NAME} -n 50>}

  Connect the dashboard (on your laptop):
    cd go-honeypot/webapp && node serve.js --api-host ${ip} --api-port ${CONTROL_PORT}
    open http://127.0.0.1:5173  →  host ${ip}, port ${CONTROL_PORT}, the auth key above

  The auth key is rotated on every daemon restart:
    sudo cat ${INSTALL_DIR}/data/auth.key

  To undo:
    sudo systemctl disable --now ${SERVICE_NAME}
    sudo cp /etc/ssh/sshd_config.honeystack-backup.* /etc/ssh/sshd_config && sudo systemctl restart ssh
    sudo ufw enable      # if you disabled it above
SUM
}

install_binary
move_real_sshd
configure_dyndns
install_service
configure_firewall
summary
