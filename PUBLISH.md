# Publish this project as a public GitHub repository

This workspace is **not** a git repo until you initialize one. Do this on your machine (or any clone that has GitHub credentials). Do **not** commit `data/`, `config.json`, or `node_modules/` — those are already gitignored.

## 1. Decide the GitHub name

Pick an owner and repo, for example `youruser/honeypot`. You will use that in:

- `git remote add origin …`
- `GITHUB_REPO` in `go-honeypot/scripts/install.sh` and Ubuntu `setup-ubuntu.sh` (for `USE_RELEASE=1`)
- optionally `go-honeypot/server/go.mod` (`module github.com/youruser/honeypot`)

## 2. What must never be uploaded

Confirm these are **not** staged:

| Path | Why |
|------|-----|
| `node_modules/` | Dependencies; reinstall with `npm ci` |
| `data/` | SQLite + dashboard password hash |
| `go-honeypot/server/data/` | Auth key, NDJSON events, SSH host key |
| `config.json` (root or `server/`) | Local port / credential overrides |
| `*.log`, `ssh_traffic.js` | Runtime leftovers |

Safe to commit: source, `config.default.json`, `package-lock.json`, `go.sum`, workflows, `setup-ubuntu.sh`, `go-honeypot/scripts/`, READMEs.

## 3. Create the public repo and push

### Option A — GitHub CLI (`gh`)

Install [GitHub CLI](https://cli.github.com/) and log in (`gh auth login`). From the project root:

```bash
cd /path/to/this/project

git init -b main
git add .
git status   # inspect: no data/, config.json, node_modules, auth.key

git commit -m "Initial commit: Node.js and Go network honeypot"

# Creates a PUBLIC repo under your account and pushes main
gh repo create honeypot --public --source=. --remote=origin --push
```

Use another name if `honeypot` is taken: `gh repo create my-honeypot --public --source=. --remote=origin --push`.

To create under an organization:

```bash
gh repo create my-org/honeypot --public --source=. --remote=origin --push
```

### Option B — GitHub website

1. Open [https://github.com/new](https://github.com/new).
2. Repository name: e.g. `honeypot`.
3. Visibility: **Public**.
4. Do **not** add a README, `.gitignore`, or license on GitHub (this tree already has them).
5. Create the repository, then locally:

```bash
cd /path/to/this/project

git init -b main
git add .
git status
git commit -m "Initial commit: Node.js and Go network honeypot"

git remote add origin git@github.com:YOURUSER/honeypot.git
# or: git remote add origin https://github.com/YOURUSER/honeypot.git

git push -u origin main
```

## 4. After the first push to `main`

GitHub Actions (`.github/workflows/go-honeypot.yml`) builds Linux/macOS/Windows binaries and publishes (or refreshes) a **`nightly`** release.

1. Wait for the **Go honeypot binaries** workflow to finish (Actions tab).
2. Open **Releases** → tag `nightly`.
3. Point installers at your repo:

```bash
# Linux/macOS
GITHUB_REPO=YOURUSER/honeypot bash go-honeypot/scripts/install.sh

# Ubuntu decoy host (download release instead of compiling)
sudo GITHUB_REPO=YOURUSER/honeypot USE_RELEASE=1 ./setup-ubuntu.sh
```

Edit the default `GITHUB_REPO=your/honeypot` in `go-honeypot/scripts/install.sh` and `install.ps1` if you want one-liner installs without env vars.

## 5. Optional: Go module path

If you want `go install github.com/YOURUSER/honeypot/server@latest` to work:

```bash
cd go-honeypot/server
go mod edit -module github.com/YOURUSER/honeypot
# keep the /server path if you prefer: github.com/YOURUSER/honeypot/server
go mod tidy
```

Commit the `go.mod` / `go.sum` change and push.

## 6. License and visibility notes

- Public means anyone can clone, fork, and see the code (including fake banners and decoy behavior).
- Add a `LICENSE` file before or right after the first push if you want an explicit license (MIT, Apache-2.0, etc.).
- Honeypots can attract abuse reports; isolate the host and check VPS terms of service.

## 7. Later updates

```bash
git add -A
git status
git commit -m "Describe the change"
git push origin main
```

Pushing to `main` rebuilds binaries and updates the `nightly` release.
