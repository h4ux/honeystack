# Push this project to GitHub (h4ux/honeystack)

The zip has no `.git` directory. Unpack it, initialize a repo, and push.
`.gitignore` already excludes runtime data, local config, and secrets.

## 1. Unpack and inspect

```bash
unzip honeystack.zip -d honeystack
cd honeystack

git init -b main
git add .
git status
```

Confirm none of these are staged:

| Path | Why |
|------|-----|
| `node_modules/` | Reinstall with `npm ci` |
| `data/` | SQLite database and dashboard password hash |
| `go-honeypot/server/data/` | Auth key, `events.ndjson`, SSH host key |
| `config.json` (root or `server/`) | Local ports and credentials |
| `*.log` | Runtime leftovers |

## 2. Push

The repository already exists at
[h4ux/honeystack](https://github.com/h4ux/honeystack), so add it as a
remote and force the first push if you are replacing the current tree:

```bash
git commit -m "Honeystack: fake-success services, history, PDF reports, Vercel dashboard"

git remote add origin git@github.com:h4ux/honeystack.git
git push -u origin main           # add --force to overwrite the existing main
```

Creating a fresh public repo instead:

```bash
gh repo create honeystack --public --source=. --remote=origin --push
```

## 3. GitHub Actions

`.github/workflows/go-honeypot.yml` cross-compiles for Linux, macOS, and
Windows on every push to `main`, then publishes a `nightly` release.

The earlier failure came from a module path mismatch: `go.mod` declared
`github.com/h4ux/honeystack/...` while the sources still imported
`github.com/example/honeypot/...`, so Go tried to clone a repository that
does not exist. Both now agree on
`github.com/h4ux/honeystack/go-honeypot/server`, and the workflow pins
Go **1.24.4** instead of reading a `go 1.25.0` directive.

You can also run it by hand from the Actions tab (`workflow_dispatch`).

## 4. Vercel

Root Directory is `go-honeypot/webapp`, framework preset **Other**, no
build command. Vercel picks up:

- the static dashboard (`index.html`, `app.js`, `pdf.js`, `style.css`)
- `api/proxy.js` as a serverless function at `/api/proxy`
- `vercel.json` for security headers

Enable **Analytics** and **Speed Insights** in the project settings; the
loader scripts are already in `index.html`.

## 5. Deploy the daemon update

```bash
cd ~/honeystack/go-honeypot/server
git pull            # or copy the new tree over
sudo env GOTOOLCHAIN=local GOFLAGS= go build -o /usr/local/bin/honeypot .
sudo systemctl restart honeypot-go
```

Open the control port so the Vercel relay can reach it:

```bash
sudo ufw allow 9090/tcp
```
