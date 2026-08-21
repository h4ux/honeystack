#!/usr/bin/env bash
#
# update-server.sh — update an installed Honeystack honeypot binary to the
# latest published build, in place, with a rollback if the new one will not
# start.
#
# Run it on the server. It finds the existing install from the systemd unit,
# compares the running commit against the latest release, and asks before it
# changes anything.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/h4ux/honeystack/main/go-honeypot/scripts/update-server.sh -o update-server.sh
#   sudo bash update-server.sh
#
#   # or piped (prompts come from /dev/tty):
#   curl -fsSL .../update-server.sh | sudo bash
#
#   # unattended:
#   curl -fsSL .../update-server.sh | sudo bash -s -- --yes
#
# Options:
#   -y, --yes            assume yes for every question
#       --check          report versions and exit without changing anything
#       --force          reinstall even when the commit already matches
#       --rollback       restore the most recent backup binary and restart
#       --repo O/N       GitHub repo (default: read from the binary, else
#                        h4ux/honeystack)
#       --tag TAG        release tag (default: nightly)
#       --binary PATH    install this local file instead of downloading
#       --service NAME   systemd unit name (default: honeypot-go)
#       --path PATH      binary path (default: from the unit, else
#                        /usr/local/bin/honeypot)
#       --keep N         how many backups to keep (default: 3)
#   -h, --help           this text

set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-honeypot-go}"
BIN_PATH=""
REPO="${GITHUB_REPO:-}"
TAG="${TAG:-nightly}"
LOCAL_BINARY=""
ASSUME_YES=0
CHECK_ONLY=0
FORCE=0
ROLLBACK=0
KEEP=3

if [[ -t 1 ]]; then
  C_B=$'\033[1;34m'; C_G=$'\033[1;32m'; C_Y=$'\033[1;33m'; C_R=$'\033[1;31m'; C_D=$'\033[2m'; C_0=$'\033[0m'
else
  C_B=""; C_G=""; C_Y=""; C_R=""; C_D=""; C_0=""
fi
log()  { printf '%s[+]%s %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '%s[✓]%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_Y" "$C_0" "$*"; }
die()  { printf '%s[x]%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }
note() { printf '    %s%s%s\n' "$C_D" "$*" "$C_0"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes)   ASSUME_YES=1; shift ;;
    --check)    CHECK_ONLY=1; shift ;;
    --force)    FORCE=1; shift ;;
    --rollback) ROLLBACK=1; shift ;;
    --repo)     REPO="${2:?}"; shift 2 ;;
    --tag)      TAG="${2:?}"; shift 2 ;;
    --binary)   LOCAL_BINARY="${2:?}"; shift 2 ;;
    --service)  SERVICE_NAME="${2:?}"; shift 2 ;;
    --path)     BIN_PATH="${2:?}"; shift 2 ;;
    --keep)     KEEP="${2:?}"; shift 2 ;;
    -h|--help)  sed -n '2,40p' "$0" | sed 's/^#\{1,\} \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

TTY_IN=""
if [[ -r /dev/tty ]] && { : </dev/tty; } 2>/dev/null; then
  TTY_IN=/dev/tty
elif [[ -t 0 ]]; then
  TTY_IN=/dev/stdin
fi

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

ask() {
  local q="$1" def="${2:-y}" hint reply
  [[ "$def" == y ]] && hint="[Y/n]" || hint="[y/N]"
  if (( ASSUME_YES )); then
    printf '    %s %s %s(--yes)%s\n' "$q" "$hint" "$C_D" "$C_0"
    [[ "$def" == y ]] && return 0 || return 1
  fi
  [[ -n "$TTY_IN" ]] || die "no terminal to ask questions on. Re-run with --yes."
  while true; do
    printf '    %s %s ' "$q" "$hint" > /dev/tty 2>/dev/null || printf '    %s %s ' "$q" "$hint"
    IFS= read -r reply < "$TTY_IN" || reply=""
    case "$(lower "${reply:-$def}")" in
      y|yes) return 0 ;;
      n|no)  return 1 ;;
      *) printf '    please answer y or n\n' ;;
    esac
  done
}

[[ $EUID -eq 0 ]] || die "run as root:  sudo bash $0"
command -v curl >/dev/null 2>&1 || die "curl is required"

UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# ---------- locate the existing install ----------
discover_install() {
  if [[ -z "$BIN_PATH" && -f "$UNIT_FILE" ]]; then
    BIN_PATH="$(awk -F'ExecStart=' '/^ExecStart=/{print $2}' "$UNIT_FILE" | awk '{print $1}' | head -n1)"
  fi
  [[ -n "$BIN_PATH" ]] || BIN_PATH="/usr/local/bin/honeypot"
  [[ -x "$BIN_PATH" ]] || die "no honeypot binary at ${BIN_PATH}. Pass --path, or run deploy-remote.sh for a first install."
}

installed_line() {
  local line
  line="$("$BIN_PATH" --version 2>/dev/null | head -n1 || true)"
  if [[ -z "$line" ]]; then
    printf '%s' "<build predates --version>"
    return
  fi
  printf '%s' "$line"
}

# The binary prints: honeypot <version> (commit <sha>, go..., os/arch)
installed_commit() {
  installed_line | sed -n 's/.*commit \([0-9a-f]\{7,40\}\).*/\1/p'
}
installed_version() {
  installed_line | awk '{print $2}'
}

# ---------- what does GitHub have? ----------
gh_api() {
  local url="$1"
  local hdr=(-fsSL -H "Accept: application/vnd.github+json")
  local token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
  [[ -n "$token" ]] && hdr+=(-H "Authorization: Bearer ${token}")
  curl "${hdr[@]}" "$url" 2>/dev/null || true
}

release_json() {
  local json
  json="$(gh_api "https://api.github.com/repos/${REPO}/releases/tags/${TAG}")"
  if [[ -z "$json" || "$json" == *'"Not Found"'* ]]; then
    json="$(gh_api "https://api.github.com/repos/${REPO}/releases/latest")"
  fi
  printf '%s' "$json"
}

# The release notes carry the commit it was built from; the title carries the
# short sha. Either is enough to compare against the running binary.
release_commit() {
  printf '%s' "$1" \
    | tr ',' '\n' \
    | sed -n 's/.*[Bb]uild from `\([0-9a-f]\{7,40\}\)`.*/\1/p;s/.*"name": *"Nightly \([0-9a-f]\{7,40\}\)".*/\1/p' \
    | head -n1
}

asset_url() {
  local json="$1" asset="$2"
  printf '%s' "$json" \
    | tr ',' '\n' \
    | grep '"browser_download_url"' \
    | grep -F "/${asset}\"" \
    | sed 's/.*"\(https[^"]*\)".*/\1/' \
    | head -n1
}

detect_asset() {
  local os arch
  case "$(lower "$(uname -s)")" in
    linux*)  os=linux ;;
    darwin*) os=darwin ;;
    *) die "unsupported OS: $(uname -s)" ;;
  esac
  case "$(lower "$(uname -m)")" in
    x86_64|amd64)  arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "no pre-built binary for $(uname -m)" ;;
  esac
  printf 'honeypot-%s-%s' "$os" "$arch"
}

# ---------- rollback ----------
do_rollback() {
  local latest
  latest="$(ls -1t "${BIN_PATH}".bak-* 2>/dev/null | head -n1 || true)"
  [[ -n "$latest" ]] || die "no backup found next to ${BIN_PATH}"
  log "restoring $latest"
  ask "Restore ${latest} over ${BIN_PATH} and restart ${SERVICE_NAME}?" y || { warn "left untouched"; exit 0; }
  systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true
  cp -a "$latest" "$BIN_PATH"
  systemctl start "${SERVICE_NAME}.service" 2>/dev/null || warn "could not start ${SERVICE_NAME}"
  sleep 2
  ok "rolled back to $(installed_line)"
  exit 0
}

discover_install

if (( ROLLBACK )); then
  do_rollback
fi

RUNNING_LINE="$(installed_line)"
RUNNING_COMMIT="$(installed_commit)"
RUNNING_VERSION="$(installed_version)"

# The binary knows which repo it came from when CI stamped it; fall back to
# the canonical one.
if [[ -z "$REPO" ]]; then
  REPO="$("$BIN_PATH" --version 2>/dev/null | sed -n 's/.*repo=\([^ )]*\).*/\1/p' | head -n1)"
fi
[[ -n "$REPO" ]] || REPO="h4ux/honeystack"

ASSET="$(detect_asset)"
JSON="$(release_json)"
LATEST_COMMIT="$(release_commit "$JSON")"
LATEST_NAME="$(printf '%s' "$JSON" | tr ',' '\n' | sed -n 's/.*"name": *"\([^"]*\)".*/\1/p' | head -n1)"

cat <<INFO

${C_B}Honeystack update check${C_0}

  service        : ${SERVICE_NAME}.service
  binary         : ${BIN_PATH}
  installed      : ${RUNNING_LINE:-<unknown: this build has no --version>}
  repo / tag     : ${REPO} @ ${TAG}
  latest release : ${LATEST_NAME:-<none found>}
  asset          : ${ASSET}

INFO

if [[ -z "$LATEST_COMMIT" && -z "$LOCAL_BINARY" ]]; then
  warn "could not read a commit from the latest release"
  note "the release must exist and its notes must mention the build commit"
fi

UP_TO_DATE=0
if [[ -n "$RUNNING_COMMIT" && -n "$LATEST_COMMIT" ]]; then
  if [[ "$LATEST_COMMIT" == "$RUNNING_COMMIT"* || "$RUNNING_COMMIT" == "$LATEST_COMMIT"* ]]; then
    UP_TO_DATE=1
  fi
fi

if (( UP_TO_DATE )); then
  ok "already running the latest published build (${RUNNING_COMMIT})"
else
  if [[ -n "$RUNNING_COMMIT" && -n "$LATEST_COMMIT" ]]; then
    warn "update available: ${RUNNING_COMMIT} -> ${LATEST_COMMIT}"
  fi
fi

if (( CHECK_ONLY )); then
  exit $(( UP_TO_DATE ? 0 : 10 ))
fi

if (( UP_TO_DATE )) && (( ! FORCE )); then
  ask "Reinstall anyway?" n || { echo "    nothing to do."; exit 0; }
fi

ask "Download and install ${ASSET} now?" y || { warn "cancelled"; exit 0; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if [[ -n "$LOCAL_BINARY" ]]; then
  [[ -f "$LOCAL_BINARY" ]] || die "no such file: $LOCAL_BINARY"
  cp "$LOCAL_BINARY" "$tmp/$ASSET"
  log "using local binary $LOCAL_BINARY"
else
  URL="$(asset_url "$JSON" "$ASSET")"
  [[ -n "$URL" ]] || URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
  log "downloading $URL"
  auth=()
  token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
  [[ -n "$token" ]] && auth=(-H "Authorization: Bearer ${token}")
  curl -fsSL "${auth[@]}" -o "$tmp/$ASSET" "$URL" || die "download failed"

  if curl -fsSL "${auth[@]}" -o "$tmp/SHA256SUMS" \
       "https://github.com/${REPO}/releases/download/${TAG}/SHA256SUMS" 2>/dev/null \
     && command -v sha256sum >/dev/null 2>&1; then
    if ( cd "$tmp" && grep -E "[[:space:]]\*?${ASSET}\$" SHA256SUMS | sha256sum -c - >/dev/null 2>&1 ); then
      ok "SHA-256 verified"
    else
      warn "checksum did NOT match"
      ask "Install it anyway?" n || die "aborted on checksum mismatch"
    fi
  else
    note "no SHA256SUMS published — skipping checksum"
  fi
fi

chmod 0755 "$tmp/$ASSET"
NEW_LINE="$("$tmp/$ASSET" --version 2>/dev/null | head -n1 || true)"
note "downloaded: ${NEW_LINE:-<build predates --version>}"

BACKUP="${BIN_PATH}.bak-$(date +%Y%m%d-%H%M%S)"
cp -a "$BIN_PATH" "$BACKUP"
ok "backup: $BACKUP"

WAS_ACTIVE=0
if systemctl is-active --quiet "${SERVICE_NAME}.service" 2>/dev/null; then
  WAS_ACTIVE=1
  log "stopping ${SERVICE_NAME}"
  systemctl stop "${SERVICE_NAME}.service"
fi

install -m 0755 "$tmp/$ASSET" "$BIN_PATH"
if command -v setcap >/dev/null 2>&1; then
  setcap 'cap_net_bind_service=+ep' "$BIN_PATH" 2>/dev/null || true
fi
ok "installed $(installed_line)"

if (( WAS_ACTIVE )) || ask "Start ${SERVICE_NAME} now?" y; then
  systemctl start "${SERVICE_NAME}.service" || warn "start failed"
  sleep 3
  if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
    ok "${SERVICE_NAME} is running the new build"
  else
    warn "${SERVICE_NAME} did not come back up"
    systemctl --no-pager --lines=20 status "${SERVICE_NAME}.service" || true
    if ask "Roll back to ${BACKUP}?" y; then
      cp -a "$BACKUP" "$BIN_PATH"
      systemctl start "${SERVICE_NAME}.service" || true
      sleep 2
      ok "rolled back to $(installed_line)"
      exit 1
    fi
  fi
fi

# Keep only the newest N backups.
if [[ "$KEEP" =~ ^[0-9]+$ ]] && (( KEEP > 0 )); then
  mapfile -t old < <(ls -1t "${BIN_PATH}".bak-* 2>/dev/null | tail -n +$((KEEP + 1)) || true)
  for f in "${old[@]:-}"; do
    [[ -n "$f" ]] && rm -f "$f" && note "removed old backup $f"
  done
fi

echo
ok "Done."
echo "  restarting rotates the auth key — reconnect the dashboard with:"
echo "    sudo cat \$(awk -F= '/WorkingDirectory=/{print \$2}' ${UNIT_FILE} 2>/dev/null)/data/auth.key"
echo "  logs: journalctl -u ${SERVICE_NAME} -f"
