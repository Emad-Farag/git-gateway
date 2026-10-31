# Git Gateway

A small web application (English GUI) that installs on the server and turns the
manual, error-prone procedure described in `git.txt` into an automatic,
center-controlled system for **several developers working on the same server and
the same applications**.

## Accounts & roles (panel login)

The GUI has its own user system (stored salted+sha256 in `~/.gitgateway/users.json`):

| Role | Can do |
|---|---|
| **admin** | Everything: permissions, hooks, users & keys, settings, service restart, all 20 git commands, manage accounts |
| **viewer** | Read-only: browse applications, commit history, status + safe commands (`status`, `log`, `blame`, `diff`, `show`, `branch`, `describe`, `tag`). Dangerous commands, permissions and settings are refused |

- The **first admin account** is created on the very first visit (username + password).
- Admins manage accounts in **Users & Keys → GUI accounts**: add, delete,
  reset password, change role. You cannot delete yourself or the last admin.
- Accounts created on old versions (single password in config.json) are
  migrated automatically into an `admin` account.
- Every user changes their own password in **Settings → Change admin password**
  (it changes *your own* account's password).

## What it does

| Manual workflow (git.txt) | Git Gateway |
|---|---|
| Edit `~/.bashrc` by hand to detect the SSH key e-mail, then fix e-mails list in every `.git/hooks/pre-commit` | One "Install" button writes both automatically and keeps them in sync |
| Allowed e-mails hard-coded inside every hook | One central **Permissions matrix** — tick a user against an application, save, hooks update instantly |
| Look at commits with `git log` in a terminal | **Commit history tab** per application (and a global feed): who, e-mail, when, message |
| Run git commands over SSH session by session | **Git command runner** in the GUI: status / add / commit / pull / push / branch / checkout / merge / stash / tag… |
| New developers need manual steps | New keys in `~/.ssh/authorized_keys` are detected automatically on rescan |

## How enforcement works

1. When a developer opens an SSH session, an installed helper script
   (`~/.gitgateway/identify.sh`) matches **his SSH-agent key fingerprint**
   against `~/.ssh/authorized_keys`, takes the e-mail from that key's comment,
   and exports `GIT_AUTHOR_EMAIL/NAME` + `GIT_COMMITTER_EMAIL/NAME` — so every
   commit is automatically stamped with *his* identity.
2. Every configured repository gets a generated `pre-commit` hook that:
   * rejects the commit if the detected e-mail is **not** on the repository's
     allowlist (maintained via the GUI),
   * rejects commits with **no verified identity** (e.g. someone connected
     without their key),
   * always re-stamps the author/committer with the verified e-mail, so a
     commit cannot be forged with someone else's name.

## Install (on the Linux server)

```bash
cd git-gateway
bash install.sh            # interactive: asks for the web port (default 8555)
bash install.sh 9000       # same, with the port as an argument
```

The installer:

1. checks `git` and `python3`, installs Flask if missing,
2. copies the app to `~/.gitgateway/app`,
3. creates **`git-gateway.service`** (systemd) so the GUI is always running
   and starts automatically on boot (`Restart=always`),
4. adds a sudoers rule limited to this one service, which makes the
   **"Restart service"** button in the GUI work without a password,
5. starts the service and prints the URL: `http://<server-ip>:<port>`.

- **First visit** asks you to create the admin password (stored salted+sha256 in `~/.gitgateway/config.json`).
- If Flask is missing: `sudo apt install python3-flask` (or let the installer create a venv).

## Changing the port later

**Settings → Web port** — edit, **Save**, then press **"Restart service & apply
port"**. The page shows exactly what is happening:

- `Saved port 8555 · running on 8555` → in sync
- `Saved port 9000 · not applied — running on 8555` → press the restart button
  (or run `sudo systemctl restart git-gateway` by hand)

## Git control via GUI

The repository page has a runner for **20 git commands**: status, log, blame,
diff, show, add, commit, restore, stash, branch, switch, checkout, merge,
rebase, cherry-pick, tag, describe, fetch, pull, push. Dangerous
ones (pull/push/checkout/merge/rebase/cherry-pick/restore/stash) require the
confirm checkbox; all arguments are validated before execution.

## Commit history

**Commit history** shows, per application (plus a global feed on the
dashboard): `When · Hash (hover for the full hash) · Author · E-mail ·
Date-time · Message`. An e-mail badge is green when that author is currently
authorized in this repository, orange if the commit came from someone who is
no longer allowed.

## Workflow after install

1. **Applications** — press *Rescan*. Every folder containing `.git` under the
   scan roots (default `~/frappe-bench/apps`, configurable in *Settings*) is listed.
2. **Users & Keys** — every e-mail found in `~/.ssh/authorized_keys` appears
   automatically (each key is fingerprinted). You may also add a manual user.
3. **Permissions** — tick which e-mail may commit to which application. Saving
   rewrites each repository's hook + allowlist file (`.git/hooks/.ggw-allowed`).
   A user with no permissions anywhere → **no commit is accepted from them**.
4. **Settings → Install identity script** — one-time. It appends a managed
   `# >>> git-gateway <<<` block to `~/.bashrc` (the old manual block can be
   removed; this one replaces it and is stricter — it matches the actual key
   used at login, not "the first e-mail it finds").
5. From then on: developers `ssh` in with their key and commit normally —
   commits are automatically signed with their name/e-mail and only succeed if
   they were granted that application.

## Security notes

- The GUI is protected by the admin password; all forms are CSRF-protected.
- The GUI git runner validates arguments — remote URLs of `push/pull/fetch`,
  `git config`, `-c` and pack-programs (`--upload-pack` etc.) are refused.
- Repositories keep any foreign (non-Gateway) hooks — a "Custom hook" badge is
  shown instead of overwriting them.
- Admin actions run as your user (the systemd service user), same as a normal
  SSH session.

## Files layout

```
git-gateway/
  app.py            Flask application (single file backend)
  templates/        English GUI
  static/style.css
  install.sh        Linux installer (systemd)
~/.gitgateway/      runtime data
  config.json       port, admin password hash, scan roots
  users.json        GUI panel accounts (username, role, salted hash)
  permissions.json  per-repo allowlists, manual users, display names
  identify.sh       SSH-identity autodetection (installed into .bashrc)
```

## Updating the code (important)

The systemd service runs **a copy** of the app at `~/.gitgateway/app` — editing
files in `/opt/git-gateway` does nothing until they are copied and the service
restarted. So after every change:

```bash
cd /opt/git-gateway
bash update.sh            # copies app.py+templates+static, restarts the service
```

Then hard-refresh the browser (Ctrl+Shift+R) to bypass CSS cache.

## Uninstall

```bash
sudo systemctl disable --now git-gateway.service
sudo rm /etc/systemd/system/git-gateway.service
rm -rf ~/.gitgateway
# hooks in each repository remain and keep enforcing; delete them with:
#   rm <repo>/.git/hooks/pre-commit <repo>/.git/hooks/.ggw-allowed
# and remove the "# >>> git-gateway >>>" block from ~/.bashrc
```
