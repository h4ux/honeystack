#!/usr/bin/env bash
#
# install.sh — download the pre-built honeypot binary that matches this
# machine's OS and architecture.
#
# Sources (first match wins, unless you force one with --from):
#   1. GitHub Release  (tag `nightly` / latest)  — produced on every
#      push to main.
#   2. GitHub Actions artifacts                  — produced on every
#      push *and* every PR to main. Requires the `gh` CLI (and a
#      token for private repos / PR artifacts).
#
# Usage:
#   ./install.sh
#   GITHUB_REPO=owner/name ./install.sh
#   ./install.sh --repo owner/name --output /usr/local/bin/honeypot
#   ./install.sh --from release
#   ./install.sh --from actions
#   ./install.sh --from actions --pr 42
#   ./install.sh --run-id 123456789
#   ./install.sh --tag nightly
#
# Environment:
#   GITHUB_REPO / GITHUB_REPOSITORY   owner/name of the GitHub repo
#   GITHUB_TOKEN / GH_TOKEN           optional; needed for private repos
#                                     and for Actions artifacts
#   INSTALL_DIR                       default: current directory
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

FROM=""            # release | actions | "" (auto)
REPO="${GITHUB_REPO:-${GITHUB_REPOSITORY:-}}"
TAG="nightly"
PR=""
RUN_ID=""
OUTPUT=""
INSTALL_DIR="${INSTALL_DIR:-.}"

usage() {
  sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
log()  { printf '==> %s\n' "$*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage ;;
    --repo)    REPO="${2:-}"; shift 2 ;;
    --from)    FROM="${2:-}"; shift 2 ;;
    --tag)     TAG="${2:-}"; shift 2 ;;
    --pr)      PR="${2:-}"; FROM="${FROM:-actions}"; shift 2 ;;
    --run-id)  RUN_ID="${2:-}"; FROM="${FROM:-actions}"; shift 2 ;;
    --output|-o) OUTPUT="${2:-}"; shift 2 ;;
    --dir)     INSTALL_DIR="${2:-}"; shift 2 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

# ---------- detect OS / arch ----------
detect_target() {
  local os arch uname_s uname_m
  uname_s="$(uname -s | tr '[:upper:]' '[:lower:]')"
  uname_m="$(uname -m | tr '[:upper:]' '[:lower:]')"

  case "$uname_s" in
    linux*)  os=linux ;;
    darwin*) os=darwin ;;
    mingw*|msys*|cygwin*|windows_nt*) os=windows ;;
    *) die "unsupported OS: $(uname -s)" ;;
  esac

  case "$uname_m" in
    x86_64|amd64)        arch=amd64 ;;
    aarch64|arm64)       arch=arm64 ;;
    armv7l|armv7|armhf)  arch=arm ;;
    i386|i686|x86)       arch=386 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac

  printf '%s %s' "$os" "$arch"
}

# ---------- repo from git remote ----------
guess_repo() {
  local url
  if ! command -v git >/dev/null 2>&1; then
    return 1
  fi
  url="$(git -C "$SCRIPT_DIR" remote get-url origin 2>/dev/null || true)"
  [[ -z "$url" ]] && url="$(git remote get-url origin 2>/dev/null || true)"
  [[ -z "$url" ]] && return 1
  # git@github.com:owner/repo.git  |  https://github.com/owner/repo.git
  url="${url%.git}"
  url="${url%/}"
  case "$url" in
    git@github.com:*)   printf '%s' "${url#git@github.com:}" ;;
    ssh://git@github.com/*) printf '%s' "${url#ssh://git@github.com/}" ;;
    https://github.com/*)   printf '%s' "${url#https://github.com/}" ;;
    http://github.com/*)    printf '%s' "${url#http://github.com/}" ;;
    *) return 1 ;;
  esac
}

auth_header() {
  local token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
  if [[ -n "$token" ]]; then
    printf 'Authorization: Bearer %s' "$token"
  fi
}

api_get() {
  local url="$1"
  local hdr=(-fsSL -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28")
  local auth
  auth="$(auth_header || true)"
  if [[ -n "$auth" ]]; then
    hdr+=(-H "$auth")
  fi
  curl "${hdr[@]}" "$url"
}

# ---------- download from a GitHub Release ----------
download_release() {
  local repo="$1" tag="$2" asset="$3" dest="$4"
  local api base json browser_url

  if [[ "$tag" == "latest" ]]; then
    api="https://api.github.com/repos/${repo}/releases/latest"
  else
    api="https://api.github.com/repos/${repo}/releases/tags/${tag}"
  fi

  log "looking up release ${tag} on ${repo}"
  if ! json="$(api_get "$api" 2>/dev/null)"; then
    if [[ "$tag" != "latest" ]]; then
      log "tag ${tag} not found, trying /releases/latest"
      json="$(api_get "https://api.github.com/repos/${repo}/releases/latest")"
    else
      return 1
    fi
  fi

  browser_url="$(printf '%s' "$json" | python3 -c "
import json,sys
rel=json.load(sys.stdin)
name=sys.argv[1]
for a in rel.get('assets') or []:
    if a.get('name')==name:
        print(a.get('browser_download_url') or '')
        break
" "$asset" 2>/dev/null || true)"

  if [[ -z "$browser_url" ]]; then
    # fallback: grep if python is missing
    browser_url="$(printf '%s' "$json" | tr ',' '\n' | sed -n "s/.*\"browser_download_url\": *\"\\([^\"]*${asset}[^\"]*\\)\".*/\\1/p" | head -n1)"
  fi
  [[ -n "$browser_url" ]] || return 1

  log "downloading ${browser_url}"
  local hdr=(-fsSL -L)
  local auth
  auth="$(auth_header || true)"
  [[ -n "$auth" ]] && hdr+=(-H "$auth")
  curl "${hdr[@]}" -o "$dest" "$browser_url"

  # checksums, if published
  local sums="${dest%/*}/SHA256SUMS"
  local sums_url
  sums_url="$(printf '%s' "$json" | python3 -c "
import json,sys
rel=json.load(sys.stdin)
for a in rel.get('assets') or []:
    if a.get('name')=='SHA256SUMS':
        print(a.get('browser_download_url') or '')
        break
" 2>/dev/null || true)"
  if [[ -n "$sums_url" ]]; then
    curl ${auth:+-H "$auth"} -fsSL -L -o "$sums" "$sums_url" || true
    if [[ -f "$sums" ]]; then
      log "verifying SHA-256"
      if command -v sha256sum >/dev/null 2>&1; then
        ( cd "$(dirname "$dest")" && grep " $(basename "$dest")\$" SHA256SUMS | sha256sum -c - )
      elif command -v shasum >/dev/null 2>&1; then
        ( cd "$(dirname "$dest")" && grep " $(basename "$dest")\$" SHA256SUMS | shasum -a 256 -c - )
      else
        log "no sha256sum/shasum on PATH; skipping checksum"
      fi
    fi
  fi
}

# ---------- download from Actions artifacts via gh ----------
download_actions() {
  local repo="$1" name="$2" dest_dir="$3"
  command -v gh >/dev/null 2>&1 || die "the GitHub CLI (gh) is required for --from actions. Install it from https://cli.github.com/"

  local run_id="$RUN_ID"
  if [[ -z "$run_id" && -n "$PR" ]]; then
    log "resolving latest successful run for PR #${PR}"
    run_id="$(gh run list --repo "$repo" --branch "$(gh pr view "$PR" --repo "$repo" --json headRefName -q .headRefName)" --workflow go-honeypot.yml --status success --limit 1 --json databaseId -q '.[0].databaseId')"
  fi
  if [[ -z "$run_id" ]]; then
    log "resolving latest successful run on main"
    run_id="$(gh run list --repo "$repo" --branch main --workflow go-honeypot.yml --status success --limit 1 --json databaseId -q '.[0].databaseId')"
  fi
  [[ -n "$run_id" ]] || die "no successful workflow run found for ${repo}"

  log "downloading artifact ${name} from run ${run_id}"
  mkdir -p "$dest_dir"
  gh run download "$run_id" --repo "$repo" --name "$name" --dir "$dest_dir"
}

# ---------- main ----------
read -r OS ARCH <<<"$(detect_target)"
ASSET="honeypot-${OS}-${ARCH}"
[[ "$OS" == "windows" ]] && ASSET="${ASSET}.exe"
ARTIFACT_NAME="honeypot-${OS}-${ARCH}"

if [[ -z "$REPO" ]]; then
  REPO="$(guess_repo || true)"
fi
[[ -n "$REPO" ]] || die "could not determine GitHub repo. Pass --repo owner/name or set GITHUB_REPO."

mkdir -p "$INSTALL_DIR"
INSTALL_DIR="$(cd "$INSTALL_DIR" && pwd)"
if [[ -z "$OUTPUT" ]]; then
  OUTPUT="${INSTALL_DIR}/honeypot"
  [[ "$OS" == "windows" ]] && OUTPUT="${OUTPUT}.exe"
fi

log "target  : ${OS}/${ARCH}"
log "repo    : ${REPO}"
log "asset   : ${ASSET}"
log "output  : ${OUTPUT}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

ok=0
if [[ -z "$FROM" || "$FROM" == "release" ]]; then
  if download_release "$REPO" "$TAG" "$ASSET" "$tmp/$ASSET"; then
    ok=1
  elif [[ "$FROM" == "release" ]]; then
    die "failed to download ${ASSET} from release ${TAG}"
  else
    log "release download failed, falling back to Actions artifacts"
  fi
fi

if [[ $ok -eq 0 ]]; then
  if [[ -z "$FROM" || "$FROM" == "actions" ]]; then
    download_actions "$REPO" "$ARTIFACT_NAME" "$tmp"
    # gh dumps the files into $tmp (or $tmp/$ARTIFACT_NAME depending on version)
    if [[ -f "$tmp/$ASSET" ]]; then
      ok=1
    elif [[ -f "$tmp/$ARTIFACT_NAME/$ASSET" ]]; then
      mv "$tmp/$ARTIFACT_NAME/$ASSET" "$tmp/$ASSET"
      ok=1
    else
      found="$(find "$tmp" -type f -name "honeypot-${OS}-${ARCH}*" | head -n1 || true)"
      [[ -n "$found" ]] || die "artifact ${ARTIFACT_NAME} did not contain ${ASSET}"
      mv "$found" "$tmp/$ASSET"
      ok=1
    fi
  fi
fi

[[ $ok -eq 1 ]] || die "could not fetch ${ASSET} from ${REPO}"

mkdir -p "$(dirname "$OUTPUT")"
cp "$tmp/$ASSET" "$OUTPUT"
chmod +x "$OUTPUT"

log "installed ${OUTPUT}"
if "$OUTPUT" --help >/dev/null 2>&1; then
  true
fi
log "run it with:  ${OUTPUT}"
