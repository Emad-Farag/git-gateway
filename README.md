# Git Gateway

A small web application (English GUI) that installs on the server and turns
multi-developer git access on shared Linux servers into an automatic,
center-controlled system: **several developers working on the same server and
the same applications**, with every commit linked to a verified SSH identity.

## Complete feature list

### Applications
- Automatic discovery of every git repository under the configured scan roots
  (default `~/frappe-bench/apps`); manual *Rescan applications* button anytime.
- Per-application page with: current branch, remote(s), ahead/behind counters,
  working-tree status, number of unsaved files.
- One-click quick actions: Write hook + allowlist, Remove hook, Status, Pull,
  Push, Stage all.

### SSH identity & authorization
- Reads developer e-mails directly from `~/.ssh/authorized_keys` key comments
  (or `environment="GIT_AUTHOR_EMAIL=..."` options) — no manual user lists.
- **SSH key manager built into the GUI**: add/remove public keys in
  `authorized_keys` with validation — no shell required. Steps to generate a
  key on Windows, Linux and macOS are included in the panel.
- Per-repository access matrix: tick which e-mail may commit to which
  application, save, hooks update instantly.
- A user with no permissions anywhere has **every commit rejected**.

### Secure SSH sessions (one Linux account, isolation per SSH key)
- Without changing how developers connect (`ssh user@server`, VS Code
  Remote-SSH), each **SSH key** can be bound to a session that sees **only the
  applications granted to its e-mail**.
- The identity is fixed server-side: the key's line in the root-owned
  `authorized_keys` gets
  `command="~/.gitgateway/ggw-session <e-mail>"`, so a client cannot claim
  another e-mail.
- The session runs inside a **bubblewrap mount namespace**: system binaries are
  read-only, the home is a per-developer workspace, granted apps are
  bind-mounted into it, and everything else on the server is **not visible**
  (kernel-enforced — not a shell wrapper that another command could bypass).
- VS Code Remote-SSH keeps working: its bootstrap commands run through the same
  forced command, inside the same namespace.
- Panel controls: per-user **Sandboxed / Full shell** switch, *Install /
  re-apply to all keys*, and an on/off toggle with a readiness check
  (bubblewrap installed, user namespaces enabled, launcher installed).
- Fails closed: if bubblewrap is missing, sandboxed keys cannot connect at all.
  Keys that already carry `command=` from another tool are never touched.
- The commit hooks also trust the session identity (bound read-only at
  `/run/ggw/session.env`), so commits stay correctly stamped — the identity
  cannot be forged by exporting variables.

### Automatic enforcement (git hooks)
- Each configured repository gets a generated hook pair
  (`pre-commit` + `post-commit`) that both source a shared verifier
  (`.git/hooks/.ggw-verify`).
- **Identity is verified at commit time by the hook itself**: it matches the
  SSH-agent fingerprints of the current session against
  `~/.ssh/authorized_keys` and derives the e-mail from the matched key.
  `GIT_COMMITTER_EMAIL` / `GIT_AUTHOR_EMAIL` values exported by the client
  shell are **ignored** — a developer cannot commit while claiming another
  user's e-mail. Keys with `environment="GIT_AUTHOR_EMAIL=..."` are
  supported too.
- `pre-commit` **refuses** the commit when the verified e-mail is not on the
  repository allowlist, or when no SSH key matches.
- A hook cannot change the environment of its parent `git commit` process, so
  the verified identity is applied by `post-commit`: any commit that git
  created with a DIFFERENT identity is instantly **amended and re-stamped**
  with the verified name/e-mail (hop-free: one amend, no hook loop).
- **Panel commits are identified by process ancestry**: the hook only trusts
  the panel identity when the commit process really descends from the
  `git-gateway.service` process. The identity is the e-mail **linked to the
  signed-in GUI account** (*Users & Keys → GUI accounts → Identity*);
  unlinked accounts cannot commit via the panel.
- An SSH-identity helper (`identify.sh`) is installed into `~/.bashrc`
  (managed `# >>> git-gateway <<<` block) to stamp shells with the correct
  name/e-mail at login.
- Hooks are re-synced automatically whenever permissions change; hooks
  written by an older version are flagged "Out of date"; broken or empty
  hook files are repaired by the *Write hook* button.
- Foreign (non-Gateway) hooks in any repository are left untouched and shown
  with a "Custom hook" badge.

### Commit history
- Per application (and a global feed on the dashboard): hash (hover shows the
  full hash), message, author, e-mail, date-time, relative time.
- Badges: green e-mail = currently authorized in this repository; orange =
  committed before being removed from the allowlist.

### Git command runner (GUI, English)
- 20 git commands from the browser: status, log, blame, diff, show, add,
  commit, restore, stash, branch, switch, checkout, merge, rebase,
  cherry-pick, tag, describe, fetch, pull, push.
- Dangerous commands (pull, push, checkout, merge, rebase, cherry-pick,
  restore, stash) require the confirm checkbox.
- Argument validation blocks remote URLs, `git config`, `-c` and pack-program
  switches (`--upload-pack` etc.).
- Output is shown full-width with automatic jump to the result.

### Accounts & roles (panel login)
- Login with **username + password**; roles:
  - **admin** — everything: permissions, hooks, users & keys, settings,
    service restart, all git commands, account management;
  - **viewer** — read-only: browse applications and commit history, safe
    commands only (`status`, `log`, `blame`, `diff`, `show`, `branch`,
    `describe`, `tag`). Write commands, permissions and settings are refused.
- Every GUI account can be linked to a **developer e-mail** (Identity):
  panel `git commit` runs are stamped with that e-mail and refused when it
  is not authorized on the target repository.
- First visit creates the first admin account (setup screen).
- Account management: add, delete, reset password, role select — you cannot
  delete yourself or the last admin.
- Passwords stored salted + SHA-256 in `~/.gitgateway/users.json`; every user
  changes their own password in Settings.
- Accounts from old single-password versions migrate automatically into an
  `admin` account.

### Keys & panel security
- All forms are CSRF-protected; Flash messages confirm every action.
- `authorized_keys` changes keep a backup copy (`authorized_keys.ggw-bak`).
- Removing a hook only removes hooks written by Git Gateway — a real custom
  hook is never deleted silently.
- Secure SSH sessions require `bubblewrap` and enabled user namespaces:
  `sudo apt install bubblewrap`, then *Users & Keys → Install / re-apply to
  all keys*. Keep SSH **key-only** on the server (`PasswordAuthentication no`):
  a password login would bypass the per-key launcher.

### Web service
- Runs as **`git-gateway.service`** (systemd): always running, starts on
  boot, auto-restarts on failure.
- Port selectable at install (`bash install.sh <port>`), changeable later in
  Settings with a *Restart service* button (passwordless sudoers rule limited
  to this one service).
- Fully mobile-responsive layout (top-bar navigation, stacked cards).

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

- **First visit** asks for an admin username + password.
- If Flask is missing: `sudo apt install python3-flask` (or let the installer
  create a venv).

## Workflow after install

1. **Applications** — press *Rescan applications*. Every folder containing
   `.git` under the scan roots is listed.
2. **Users & Keys** — every e-mail found in `~/.ssh/authorized_keys` appears
   automatically. New keys can be added from the same page (with per-OS
   instructions for the developers), or a manual user can be added.
3. **Permissions** — tick which e-mail may commit to which application.
   Saving rewrites each repository's hook + allowlist file
   (`.git/hooks/.ggw-allowed`).
4. **Settings → Install identity script** — one-time. It appends the managed
   `# >>> git-gateway <<<` block to `~/.bashrc`.
5. **Users & Keys → Secure SSH sessions** (optional but recommended) —
   `sudo apt install bubblewrap` on the server, then press
   *Install / re-apply to all keys* and **Enable secure sessions**. Each
   developer's key then opens a session that contains only the applications
   granted to that e-mail; the administrator's own key stays on *Full shell*.
6. From then on: developers `ssh` in with their key and commit normally —
   commits are automatically signed with their name/e-mail and only succeed
   if they were granted that application.

## Changing the port later

**Settings → Web port** — edit, **Save**, then press **"Restart service &
apply port"**. The page shows exactly what is happening:

- `Saved port 8555 · running on 8555` → in sync
- `Saved port 9000 · not applied — running on 8555` → press the restart
  button (or run `sudo systemctl restart git-gateway` by hand)

## Files layout

```
git-gateway/
  app.py            Flask application (single file backend)
  templates/        English GUI
  static/style.css
  install.sh        Linux installer (systemd)
  update.sh         applies code changes to the running install
  uninstall.sh      full removal
~/.gitgateway/      runtime data
  app/              the running copy of app.py + templates + static
  config.json       port, secret, scan roots
  users.json        GUI panel accounts (username, role, salted hash)
  permissions.json  per-repo allowlists, manual users, display names
  identify.sh       SSH-identity autodetection (installed into .bashrc)
  ggw-session      secure-session launcher (forced command of sandboxed keys)
  sessions/*.env   per-e-mail identity bound read-only into its session
  work/<email>/    per-developer writable home inside the sandbox
```

## Updating the code (important)

The systemd service runs **a copy** of the app at `~/.gitgateway/app` —
editing files in `/opt/git-gateway` does nothing until they are copied and
the service restarted. So after every change:

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
#   rm <repo>/.git/hooks/pre-commit <repo>/.git/hooks/post-commit \
#      <repo>/.git/hooks/.ggw-verify <repo>/.git/hooks/.ggw-allowed
# and remove the "# >>> git-gateway <<<" block from ~/.bashrc
```
