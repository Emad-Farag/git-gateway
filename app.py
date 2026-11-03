"""
Git Gateway — web GUI to control multi-developer git identity & authorization
on one server.

- Discovers every git repository under the configured roots (e.g. ~/frappe-bench/apps)
- Reads all e-mails registered in ~/.ssh/authorized_keys
- Lets an admin grant per-user (e-mail) access per repository via a GUI matrix
- Auto-installs pre/post-commit hooks to every repository that verify the
  committer's SSH key at commit time and only allow authorized e-mails
- Shows every commit of every application in the GUI (who / when / what)
- Runs git commands (pull / push / add / commit / branch / ...) from the GUI

Intended for an internal Linux server protected by SSH; the GUI itself is
protected by an admin password. Files are stored under ~/.gitgateway/.
"""

import os
import re
import json
import time
import hmac
import shlex
import threading
import subprocess
import hashlib
import secrets
import datetime
import shutil
from functools import wraps

import markupsafe
from flask import (Flask, request, session, redirect, url_for,
                   render_template, flash, abort)

# --------------------------------------------------------------------------
# Environment / storage
# --------------------------------------------------------------------------
APP_DIR     = os.path.dirname(os.path.abspath(__file__))
HOME        = os.path.expanduser("~")
DATA_DIR    = os.path.join(HOME, ".gitgateway")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
STATE_PATH  = os.path.join(DATA_DIR, "permissions.json")
SSH_KEYS    = os.path.join(HOME, ".ssh", "authorized_keys")
BASHRC      = os.path.join(HOME, ".bashrc")
HOOK_MARKER = "Git Gateway"
IDENTIFY_SH = os.path.join(DATA_DIR, "identify.sh")
SESSION_SH  = os.path.join(DATA_DIR, "ggw-session")
WORK_ROOT   = os.path.join(DATA_DIR, "work")
LOCK        = threading.RLock()

DEFAULT_CONFIG = {
    "port": 8555,
    "password_hash": None,
    "password_salt": None,
    "secret": None,
    "scan_roots": [os.path.join(HOME, "frappe-bench", "apps")],
    "sandbox_enabled": False,   # secure SSH sessions (bubblewrap) on/off
    "sandbox_allow_fallback": False,  # allow a normal shell if bwrap is missing
    "ssh_modes": {},            # email -> "sandbox" | "full"
}

DEFAULT_STATE = {
    "manual_emails": [],   # e-mails added by the admin (without an SSH key)
    "display_names": {},   # email -> name used for GIT_AUTHOR_NAME
    "allowed": {},         # repo_path -> [email, ...]
}


def cfg_get(key, default=None):
    with LOCK:
        try:
            cfg = json.load(open(CONFIG_PATH, encoding="utf-8"))
        except Exception:
            cfg = {}
    return cfg.get(key, DEFAULT_CONFIG.get(key, default))


def cfg_set(**kw):
    with LOCK:
        try:
            cfg = json.load(open(CONFIG_PATH, encoding="utf-8"))
        except Exception:
            cfg = {}
        cfg.update(kw)
        os.makedirs(DATA_DIR, exist_ok=True)
        json.dump(cfg, open(CONFIG_PATH, "w", encoding="utf-8"), indent=2)


def state_get():
    with LOCK:
        try:
            st = json.load(open(STATE_PATH, encoding="utf-8"))
        except Exception:
            st = {}
    st.setdefault("manual_emails", [])
    st.setdefault("display_names", {})
    st.setdefault("allowed", {})
    return st


def state_set(st):
    with LOCK:
        os.makedirs(DATA_DIR, exist_ok=True)
        json.dump(st, open(STATE_PATH, "w", encoding="utf-8"), indent=2)


# --------------------------------------------------------------------------
# GUI accounts (username + password + role) — for the web panel itself
# Roles: "admin"   full control (permissions, hooks, users, settings, all git cmds)
#        "viewer"  read-only   (browse applications & commits, safe read cmds only)
# --------------------------------------------------------------------------
USERS_PATH = os.path.join(DATA_DIR, "users.json")
ROLES      = ("admin", "viewer")


def _pw_hash(pw, salt):
    return hashlib.sha256((salt + pw).encode()).hexdigest()


def gui_users():
    try:
        return json.load(open(USERS_PATH, encoding="utf-8"))
    except Exception:
        return []


def save_gui_users(users):
    with LOCK:
        os.makedirs(DATA_DIR, exist_ok=True)
        json.dump(users, open(USERS_PATH, "w", encoding="utf-8"), indent=2)


def find_gui_user(username):
    for u in gui_users():
        if u.get("username") == username:
            return u
    return None


def create_gui_user(username, password, role):
    users = [u for u in gui_users() if u.get("username") != username]
    salt = secrets.token_hex(16)
    users.append({"username": username, "salt": salt,
                  "hash": _pw_hash(password, salt), "role": role})
    save_gui_users(users)


def gui_admins_count():
    return sum(1 for u in gui_users() if u.get("role") == "admin")


def migrate_legacy_admin_password():
    """Versions before 1.1 stored a single admin password in config.json —
    turn it into a proper 'admin' account so nothing is lost on upgrade."""
    if gui_users() or not cfg_get("password_hash") or not cfg_get("password_salt"):
        return
    save_gui_users([{"username": "admin", "salt": cfg_get("password_salt"),
                     "hash": cfg_get("password_hash"), "role": "admin"}])


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


def run(args, cwd=None, timeout=90, extra_env=None):
    """Run a command, return dict(ok, code, out, err). Never raises."""
    try:
        env = None
        if extra_env:
            env = os.environ.copy()
            env.update(extra_env)
        p = subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout, shell=False, env=env)
        return {"ok": p.returncode == 0, "code": p.returncode,
                "out": p.stdout or "", "err": p.stderr or ""}
    except subprocess.TimeoutExpired:
        return {"ok": False, "code": -1, "out": "", "err": "Timeout after %ss" % timeout}
    except Exception as e:
        return {"ok": False, "code": -1, "out": "", "err": str(e)}


def rel_time(ts):
    if not ts:
        return ""
    d = time.time() - int(ts)
    if d < 60:        return "just now"
    if d < 3600:      return "%dm ago" % (d // 60)
    if d < 86400:     return "%dh ago" % (d // 3600)
    if d < 2592000:   return "%dd ago" % (d // 86400)
    if d < 31104000:  return "%dmo ago" % max(1, d // 2592000)
    return "%dy ago" % max(1, d // 31104000)


def display_name_of(email, st=None):
    st = st or state_get()
    if email in st["display_names"]:
        return st["display_names"][email]
    parts = re.split(r"[._\-]+", email.split("@")[0])
    return " ".join(p.capitalize() for p in parts if p) or email


# --------------------------------------------------------------------------
# Repository discovery
# --------------------------------------------------------------------------
SKIP_DIRS = {"node_modules", "venv", ".venv", "__pycache__", "vendor",
             "dist", "build", "env", "site-packages"}


def find_repos():
    """Scan configured roots and return sorted list of repository paths."""
    repos = set()
    for root in cfg_get("scan_roots") or []:
        root = os.path.expanduser(root)
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, _ in os.walk(root):
            if ".git" in dirnames:
                repos.add(os.path.abspath(dirpath))
                dirnames[:] = []          # found a repo: don't walk inside it
                continue
            if os.path.relpath(dirpath, root).count(os.sep) >= 5:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames
                           if not d.startswith(".") and d not in SKIP_DIRS]
    return sorted(repos)


def repo_meta(path, quick=True):
    g = lambda *a: run(["git"] + list(a), cwd=path, timeout=30)
    meta = {"path": path, "id": path, "name": os.path.basename(path)}

    meta["branch"] = g("branch", "--show-current")["out"].strip() or "(detached)"
    meta["remote"] = g("config", "--get", "remote.origin.url")["out"].strip()

    meta["last"] = None
    r = g("log", "-1", "--pretty=format:%H\x1f%an\x1f%ae\x1f%at\x1f%s")
    if r["ok"] and r["out"].strip():
        p = r["out"].strip().split("\x1f")
        if len(p) == 5:
            meta["last"] = {"hash": p[0][:8], "author": p[1], "email": p[2],
                            "when": rel_time(p[3]), "msg": p[4]}

    meta["dirty"] = sum(1 for l in g("status", "--porcelain")["out"].splitlines() if l.strip())
    meta["ahead"] = meta["behind"] = None
    if meta["remote"]:
        r = g("rev-list", "--left-right", "--count", "HEAD...@{upstream}")
        if r["ok"]:
            try:
                a, b = [int(x) for x in r["out"].split()]
                meta["ahead"], meta["behind"] = a, b
            except ValueError:
                pass
    return meta


def hook_state(path, st=None):
    st = st or state_get()
    hooks = os.path.join(path, ".git", "hooks")
    files = {"pre-commit": HOOK_PRE_TEMPLATE, "post-commit": HOOK_POST_TEMPLATE,
             ".ggw-verify": HOOK_COMMON}
    states = []
    for name, tpl in files.items():
        p = os.path.join(hooks, name)
        if not os.path.isfile(p):
            states.append("missing")
            continue
        try:
            content = open(p, encoding="utf-8", errors="ignore").read()
        except Exception:
            states.append("missing")
            continue
        stripped = content.strip()
        if len(stripped) <= 2:
            states.append("empty")          # broken stub (e.g. saved by an editor)
        elif HOOK_MARKER not in content:
            states.append("foreign")        # someone else's hook — leave alone
        elif stripped != tpl.strip():
            states.append("stale")          # ours but written by an older version
        else:
            states.append("installed")
    if all(s == "installed" for s in states):
        try:
            have = sorted(l for l in open(os.path.join(hooks, ".ggw-allowed"),
                                          encoding="utf-8").read().splitlines() if l)
        except Exception:
            have = None
        expected = sorted(st["allowed"].get(path, []))
        return "stale" if have != expected else "installed"
    if "foreign" in states:
        return "foreign"
    if "empty" in states:
        return "empty"
    if "missing" in states:
        return "missing"
    return "stale"


# --------------------------------------------------------------------------
# ~/.ssh/authorized_keys parsing
# --------------------------------------------------------------------------
def parse_authorized_keys():
    """Return list of {index, emails, fingerprints, type, comment}."""
    if not os.path.isfile(SSH_KEYS):
        return []
    fps = run(["ssh-keygen", "-lf", SSH_KEYS], timeout=20)["out"].splitlines()
    fps = [l for l in fps if re.search(r"SHA256:|([0-9a-f]{2}:){7}", l)]
    entries = []
    with open(SSH_KEYS, encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            env_e = re.findall(r'environment="[^"]*?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})', line)
            all_e = list(dict.fromkeys(env_e + EMAIL_RE.findall(line)))
            entries.append({
                "index": i,
                "raw": line,
                "emails": all_e,
                "type": line.split()[0] if line.split() else "",
                "fingerprints": fps[i] if i < len(fps) else "",
                "comment": line.split()[-1] if len(line.split()) > 2 else "",
                "secure": 'command="' in line and SESSION_SH in line,
            })
    return entries


def ssh_emails():
    out = set()
    for e in parse_authorized_keys():
        out.update(e["emails"])
    return out


def all_emails():
    st = state_get()
    return sorted(ssh_emails() | set(st["manual_emails"]))


# --------------------------------------------------------------------------
# Hooks & identity auto-install
# --------------------------------------------------------------------------
# The verification logic lives in ONE shared generated file
# (.git/hooks/.ggw-verify) sourced by BOTH hooks, so the code exists once.
# pre-commit  : refuses a commit whose verified identity is not allowed.
# post-commit : re-stamps (amends) a commit that git itself created with a
#               DIFFERENT identity than the verified one (a pre-commit hook
#               cannot modify the environment of its parent git process).
HOOK_COMMON = r"""# Git Gateway identity verification - sourced by pre-commit/post-commit.
# Installed by Git Gateway (auto-generated) - DO NOT EDIT.
# Sets on success: GGW_EMAIL, GGW_NAME, GGW_VIA. Exits 1 (deny) on failure.

deny () {
  echo "==================================================" >&2
  echo "Git Gateway: $1" >&2
  echo "This repository only accepts commits from authorized users." >&2
  echo "Connect with your authorized SSH key, or ask the administrator" >&2
  echo "to grant you access in Git Gateway." >&2
  echo "==================================================" >&2
  exit 1
}

allow_file="$(git rev-parse --git-dir 2>/dev/null)/hooks/.ggw-allowed"
[ -f "$allow_file" ] || deny "No allowlist is installed for this repository."

email=""; name=""; via=""

# --- 1) commit made by the Git Gateway panel service itself? ---------------
# Walk the parent-process chain: only processes that really descend from the
# git-gateway service qualify (an interactive shell cannot fake its ancestry).
_gg_p=$$
_gg_i=0
while [ "$_gg_i" -lt 25 ]; do
  _gg_i=$((_gg_i+1))
  [ -r "/proc/$_gg_p/cmdline" ] || break
  _gg_cl="$(tr '\0' ' ' < "/proc/$_gg_p/cmdline" 2>/dev/null)"
  _gg_cg="$(cat "/proc/$_gg_p/cgroup" 2>/dev/null)"
  case "$_gg_cl|$_gg_cg" in
    *git-gateway*|*gitgateway*)
      via="panel"
      email="${GIT_GGW_PANEL_EMAIL:-}"
      name="${GIT_GGW_PANEL_NAME:-}"
      break ;;
  esac
  _gg_pp="$(awk '/^PPid:/{print $2}' "/proc/$_gg_p/status" 2>/dev/null)"
  [ -n "$_gg_pp" ] || break
  [ "$_gg_pp" = "1" ] && break
  _gg_p="$_gg_pp"
done

# --- 2) sandboxed SSH session? identity is fixed server-side in
#        authorized_keys and bound read-only into the session's namespace ---
if [ -z "$via" ] && [ -r /run/ggw/session.env ]; then
  GGW_SESSION_EMAIL=""; GGW_SESSION_NAME=""
  . /run/ggw/session.env
  if [ -n "$GGW_SESSION_EMAIL" ]; then
    via="sandbox"
    email="$GGW_SESSION_EMAIL"
    name="$GGW_SESSION_NAME"
  fi
fi

# --- 3) otherwise the SSH agent key decides (client GIT_* values ignored) ---
if [ -z "$via" ] && [ -f "$HOME/.ssh/authorized_keys" ]; then
  _gg_keys="$HOME/.ssh/authorized_keys"
  _gg_fps="$(ssh-add -l 2>/dev/null | grep -v 'no identities')"
  _gg_all="$(ssh-keygen -lf "$_gg_keys" 2>/dev/null)"
  if [ -n "$_gg_fps" ] && [ -n "$_gg_all" ]; then
    for _gg_fp in $(printf '%s\n' "$_gg_fps" | grep -o 'SHA256:[A-Za-z0-9+/=]*'); do
      _gg_l="$(printf '%s\n' "$_gg_all" | grep -F "$_gg_fp" | head -n 1)"
      [ -n "$_gg_l" ] || continue
      email="$(printf '%s\n' "$_gg_l" | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+[.][a-zA-Z]{2,}' | head -n 1)"
      [ -n "$email" ] && { via="ssh-key"; break; }
    done
    if [ -z "$email" ]; then
      # Some keys carry their identity in an environment="GIT_AUTHOR_EMAIL=..."
      # option instead of the comment — match against the raw file lines for it.
      while IFS= read -r _gg_raw; do
        case "$_gg_raw" in ""|"#"*) continue ;; esac
        _gg_l="$(printf '%s\n' "$_gg_raw" | ssh-keygen -lf - 2>/dev/null | head -n 1)"
        [ -n "$_gg_l" ] || continue
        _gg_fp2="$(printf '%s\n' "$_gg_l" | grep -o 'SHA256:[A-Za-z0-9+/=]*')"
        [ -n "$_gg_fp2" ] || _gg_fp2="$(printf '%s\n' "$_gg_l" | grep -oE '([0-9a-f]{2}:){15}[0-9a-f]{2}')"
        [ -n "$_gg_fp2" ] || continue
        printf '%s\n' "$_gg_fps" | grep -qF "$_gg_fp2" || continue
        email="$(printf '%s\n' "$_gg_raw" | grep -oE 'GIT_AUTHOR_EMAIL=[^"]+' | head -n 1 | sed 's/.*=//')"
        [ -n "$email" ] && { via="ssh-key"; break; }
      done < "$_gg_keys"
    fi
  fi
fi

[ -n "$email" ] || deny "Cannot verify your identity: no matching SSH key. Connect with your
authorized SSH key (run 'ssh-add') and try again."

grep -ixF "$email" "$allow_file" >/dev/null 2>&1 \
  || deny "You are NOT authorized to commit to this repository (verified identity: $email)."

if [ -z "$name" ]; then
  name="$(printf %s "$email" | cut -d@ -f1 | tr '._-' '  ' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2); print}')"
fi

GGW_EMAIL="$email"; GGW_NAME="$name"; GGW_VIA="$via"
export GGW_EMAIL GGW_NAME GGW_VIA
"""

HOOK_PRE_TEMPLATE = r"""#!/bin/bash
# Installed by Git Gateway (auto-generated) - DO NOT EDIT
# pre-commit: verify the committer's SSH identity BEFORE accepting the commit.
# GIT_* values forged by the client shell are IGNORED — the SSH agent decides.
_dir="$(git rev-parse --git-dir 2>/dev/null)"
[ -n "$_dir" ] || exit 1
if [ ! -f "$_dir/hooks/.ggw-verify" ]; then
  echo "Git Gateway: hook files are incomplete - run 'Refresh all hooks' in the panel." >&2
  exit 1
fi
. "$_dir/hooks/.ggw-verify"
exit 0
"""

HOOK_POST_TEMPLATE = r"""#!/bin/bash
# Installed by Git Gateway (auto-generated) - DO NOT EDIT
# post-commit: a hook cannot change the environment of its parent 'git commit'
# process, so the VERIFIED identity is enforced here. If the commit that was
# just made carries anything but the verified e-mail, it is amended NOW.
[ "$GIT_GGW_AMEND" = "1" ] && exit 0
_dir="$(git rev-parse --git-dir 2>/dev/null)"
[ -n "$_dir" ] || exit 0
[ -f "$_dir/hooks/.ggw-verify" ] || exit 0
. "$_dir/hooks/.ggw-verify" || exit 0
[ -n "$GGW_EMAIL" ] || exit 0
_ae="$(git log -1 --format='%ae' 2>/dev/null)"
_ce="$(git log -1 --format='%ce' 2>/dev/null)"
[ "$_ae" = "$GGW_EMAIL" ] && [ "$_ce" = "$GGW_EMAIL" ] && exit 0
GIT_GGW_AMEND=1 GIT_AUTHOR_NAME="$GGW_NAME" GIT_AUTHOR_EMAIL="$GGW_EMAIL" \
GIT_COMMITTER_NAME="$GGW_NAME" GIT_COMMITTER_EMAIL="$GGW_EMAIL" \
  git -c commit.gpgsign=false commit --amend --no-edit --reset-author -q >/dev/null 2>&1 \
  && echo "Git Gateway: commit re-stamped as $GGW_NAME <$GGW_EMAIL>" >&2
exit 0
"""


def _write_hook_file(hook, template, mode):
    """Sync one generated hook file; return True if (re)written now."""
    need_write = not os.path.isfile(hook)
    if os.path.isfile(hook):
        try:
            content = open(hook, encoding="utf-8", errors="ignore").read()
        except Exception:
            content = ""
        if HOOK_MARKER in content:
            need_write = content.strip() != template.strip()  # ours: keep in sync
        elif len(content.strip()) <= 2:
            need_write = True    # broken/empty stub — replace it
        # else: foreign hook — leave it alone (shown as "Custom hook" in the GUI)
    if need_write:
        with open(hook, "w", encoding="utf-8", newline="\n") as f:
            f.write(template)
        os.chmod(hook, mode)
    return need_write


def install_hook(repo_path, emails):
    """Write the allowlist and the pre/post-commit hook pair for one repository."""
    hooks = os.path.join(repo_path, ".git", "hooks")
    os.makedirs(hooks, exist_ok=True)
    allow = os.path.join(hooks, ".ggw-allowed")
    with open(allow, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(set(emails))) + ("\n" if emails else ""))
    os.chmod(allow, 0o644)
    # verify first, so the sourced file exists before the hooks reference it
    _write_hook_file(os.path.join(hooks, ".ggw-verify"), HOOK_COMMON, 0o644)
    _write_hook_file(os.path.join(hooks, "pre-commit"),  HOOK_PRE_TEMPLATE,  0o755)
    _write_hook_file(os.path.join(hooks, "post-commit"), HOOK_POST_TEMPLATE, 0o755)


def refresh_hooks():
    """Write hooks for every repository that has permissions configured."""
    st = state_get()
    done = 0
    for path, emails in st["allowed"].items():
        if os.path.isdir(path):
            install_hook(path, emails)
            done += 1
    return done


IDENTIFY_SH_BODY = r"""#!/bin/bash
# >>> Git Gateway identity detection (auto-generated) - DO NOT EDIT <<<
# Detects which authorized SSH key started this session and exports
# GIT_AUTHOR_* / GIT_COMMITTER_* so every commit is stamped with its owner.

_gg_email=""
_gg_keys="$HOME/.ssh/authorized_keys"
_gg_agent="$(ssh-add -l 2>/dev/null)"

if [ -n "$_gg_agent" ] && [ -f "$_gg_keys" ] && \
   ! printf '%s' "$_gg_agent" | grep -q "no identities"; then
  _gg_all="$(ssh-keygen -lf "$_gg_keys" 2>/dev/null)"
  while IFS= read -r _gg_line; do
    _gg_fp="$(printf '%s' "$_gg_line" | grep -o 'SHA256:[A-Za-z0-9+/=]*')"
    if [ -z "$_gg_fp" ]; then
      _gg_fp="$(printf '%s' "$_gg_line" | grep -oE '([0-9a-f]{2}:){15}[0-9a-f]{2}')"
    fi
    if [ -n "$_gg_fp" ] && printf '%s' "$_gg_agent" | grep -qF "$_gg_fp"; then
      _gg_email="$(printf '%s' "$_gg_line" | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | head -n 1)"
      [ -n "$_gg_email" ] && break
    fi
  done <<EOF
$_gg_all
EOF
fi

if [ -n "$_gg_email" ]; then
  export GIT_AUTHOR_EMAIL="$_gg_email"
  export GIT_COMMITTER_EMAIL="$_gg_email"
  _gg_name="$(printf %s "$_gg_email" | cut -d@ -f1 | tr '._-' '  ' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2); print}')"
  export GIT_AUTHOR_NAME="$_gg_name"
  export GIT_COMMITTER_NAME="$_gg_name"
fi

unset _gg_agent _gg_all _gg_line _gg_fp _gg_email _gg_name _gg_keys
# <<< Git Gateway identity detection <<<
"""

BASHRC_START = "# >>> git-gateway >>>"
BASHRC_END   = "# <<< git-gateway <<<"
BASHRC_BLOCK = (
    BASHRC_START + "\n"
    "if [ -n \"$SSH_CONNECTION\" ] && [ -f \"$HOME/.gitgateway/identify.sh\" ]; then\n"
    "  . \"$HOME/.gitgateway/identify.sh\"\n"
    "fi\n" +
    BASHRC_END + "\n"
)


def bashrc_status():
    try:
        return "installed" if BASHRC_START in open(BASHRC, encoding="utf-8", errors="ignore").read() else "missing"
    except Exception:
        return "missing"


def install_bashrc_block():
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(IDENTIFY_SH, "w", encoding="utf-8", newline="\n") as f:
        f.write(IDENTIFY_SH_BODY)
    os.chmod(IDENTIFY_SH, 0o755)
    try:
        cur = open(BASHRC, encoding="utf-8", errors="ignore").read()
    except Exception:
        cur = ""
    cur = re.sub(re.escape(BASHRC_START) + r".*?" + re.escape(BASHRC_END) + r"\n?",
                 "", cur, flags=re.S).rstrip("\n")
    with open(BASHRC, "w", encoding="utf-8", errors="ignore") as f:
        f.write(cur + "\n\n" + BASHRC_BLOCK)


# --------------------------------------------------------------------------
# Secure SSH sessions (bubblewrap) — one Linux user, isolation per SSH key
# --------------------------------------------------------------------------
# authorized_keys lines of sandboxed keys become:
#   command="/home/<user>/.gitgateway/ggw-session <email>" ssh-ed25519 AAAA...
# The e-mail is fixed server-side (authorized_keys is root-owned), so a
# client cannot claim another identity. The session then runs inside a
# bubblewrap mount namespace containing ONLY the apps granted to that
# e-mail; the rest of the server is not visible (kernel-enforced).
SESSION_SCRIPT_BODY = r'''#!/usr/bin/env python3
# Git Gateway secure SSH session (auto-generated) - DO NOT EDIT
# sshd runs this for keys whose authorized_keys line carries:
#   command="<this script> <e-mail>"
# The e-mail comes from a root-owned file, so the client cannot change it.
import json
import os
import shutil
import sys

DATA_DIR = os.path.dirname(os.path.abspath(__file__))
HOME     = os.path.expanduser("~")
CONFIG   = os.path.join(DATA_DIR, "config.json")
STATE    = os.path.join(DATA_DIR, "permissions.json")
WORK     = os.path.join(DATA_DIR, "work")
SESSIONS = os.path.join(DATA_DIR, "sessions")
BWRAP    = shutil.which("bwrap")


def die(msg):
    sys.stderr.write("\nGit Gateway: %s\n\n" % msg)
    sys.exit(1)


def load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def slug(email):
    return email.replace("@", "_at_").replace("/", "_")


def main():
    if len(sys.argv) < 2:
        die("session identity missing — press 'Apply secure modes to keys' in the panel.")
    email = sys.argv[1].strip().lower()
    if "@" not in email or "/" in email or len(email) > 200:
        die("invalid session identity")
    cfg = load(CONFIG, {})
    if not cfg.get("sandbox_enabled"):
        die("secure SSH sessions are disabled in the panel (Users & Keys).")
    if not BWRAP:
        if cfg.get("sandbox_allow_fallback"):
            os.environ["GGW_SESSION_EMAIL"] = email
            die("bubblewrap missing — fallback would be an unprotected shell; "
                "install it with: sudo apt install bubblewrap")
        die("bubblewrap is not installed, so a secure session cannot start.\n"
            "  sudo apt install bubblewrap\n"
            "Then reload the panel and press 'Apply secure modes to keys'.")
    st = load(STATE, {})
    allowed = st.get("allowed", {}) or {}
    roots = [os.path.realpath(r) for r in (cfg.get("scan_roots") or
             [os.path.join(HOME, "frappe-bench", "apps")])]
    apps = {}
    for path, emails in allowed.items():
        if email not in [str(e).lower() for e in emails]:
            continue
        if not os.path.isdir(path):
            continue
        real = os.path.realpath(path)
        if not any(real == r or real.startswith(r + os.sep) for r in roots):
            continue
        apps[os.path.basename(path.rstrip("/"))] = real
    apps = sorted(apps.items())

    # writable per-developer home (holds ~/.vscode-server and the app mounts)
    ws = os.path.join(WORK, slug(email))
    os.makedirs(os.path.join(ws, "frappe-bench", "apps"), exist_ok=True)

    name = (st.get("display_names") or {}).get(email) or \
        email.split("@")[0].replace(".", " ").replace("_", " ").replace("-", " ").title()
    name = name.replace('"', "").replace("\\", "")

    # identity file for the commit hooks: bound read-only at /run/ggw/session.env
    os.makedirs(SESSIONS, exist_ok=True)
    env_path = os.path.join(SESSIONS, slug(email) + ".env")
    fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write('GGW_SESSION_EMAIL=%s\nGGW_SESSION_NAME="%s"\n' % (email, name))
    os.chmod(env_path, 0o600)

    user = os.environ.get("USER") or os.path.basename(HOME)
    argv = [BWRAP, "--unshare-user", "--unshare-pid", "--unshare-uts",
            "--unshare-ipc", "--die-with-parent", "--new-session",
            "--ro-bind", "/usr", "/usr",
            "--symlink", "usr/bin", "/bin",
            "--symlink", "usr/sbin", "/sbin",
            "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/lib64", "/lib64",
            "--dir", "/home",
            "--bind", ws, HOME,
            "--ro-bind", "/etc", "/etc",
            "--ro-bind-try", "/opt", "/opt",
            "--proc", "/proc", "--dev", "/dev",
            "--tmpfs", "/dev/shm", "--tmpfs", "/tmp", "--tmpfs", "/run",
            "--dir", "/run/ggw",
            "--ro-bind", env_path, "/run/ggw/session.env"]
    for app_name, app_path in apps:
        argv += ["--bind", app_path, HOME + "/frappe-bench/apps/" + app_name]
    sock = os.environ.get("SSH_AUTH_SOCK")
    if sock and os.path.exists(sock):
        argv += ["--bind", sock, "/run/ggw/agent.sock",
                 "--setenv", "SSH_AUTH_SOCK", "/run/ggw/agent.sock"]
    start = HOME + "/frappe-bench/apps/" + apps[0][0] if apps else HOME
    argv += ["--chdir", start,
             "--setenv", "HOME", HOME,
             "--setenv", "USER", user, "--setenv", "LOGNAME", user,
             "--setenv", "SHELL", "/bin/bash",
             "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
             "--setenv", "GIT_AUTHOR_NAME", name,
             "--setenv", "GIT_AUTHOR_EMAIL", email,
             "--setenv", "GIT_COMMITTER_NAME", name,
             "--setenv", "GIT_COMMITTER_EMAIL", email,
             "--setenv", "GGW_SESSION_EMAIL", email]
    cmd = os.environ.get("SSH_ORIGINAL_COMMAND") or ""
    if cmd:
        argv += ["--", "bash", "-lc", cmd]      # VS Code Remote-SSH bootstrapping
    else:
        argv += ["--", "bash", "-l"]
    os.execv(BWRAP, argv)


if __name__ == "__main__":
    main()
'''


def install_session_script():
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(SESSION_SH, "w", encoding="utf-8", newline="\n") as f:
        f.write(SESSION_SCRIPT_BODY)
    os.chmod(SESSION_SH, 0o755)
    os.makedirs(WORK_ROOT, exist_ok=True)


def sandbox_status():
    """Report whether kernel-level secure sessions can run on this server."""
    bwrap = bool(shutil.which("bwrap"))
    userns = True
    try:
        userns = open("/proc/sys/kernel/unprivileged_userns_clone").read().strip() != "0"
    except Exception:
        pass                     # sysctl absent → user namespaces allowed by default
    return {"bwrap": bwrap, "userns": userns,
            "script": os.path.isfile(SESSION_SH),
            "enabled": bool(cfg_get("sandbox_enabled")),
            "fallback": bool(cfg_get("sandbox_allow_fallback"))}


def ssh_mode_of(email):
    modes = cfg_get("ssh_modes") or {}
    return modes.get(email, "sandbox")


# SSH option prefix (comma/space separated key=value pairs) + key + comment
KEY_TYPE_RE = (r"(?:ssh-(?:rsa|dss|ed25519(?:-sk)?)|ecdsa-sha2-nistp\d{3}(?:-sk)?"
               r"|sk-(?:ssh-ed25519|ecdsa-sha2-nistp\d{3})@openssh\.com)")
_KEY_LINE_RE = re.compile(r'(?:^|\s)(' + KEY_TYPE_RE + r')\s+([A-Za-z0-9+/=]{40,})\s*(.*)$')


def _split_key_line(line):
    """(options, type, base64, comment) — options may contain quotes/commas."""
    s = line.strip()
    m = _KEY_LINE_RE.search(s)
    if not m:
        return None
    return (s[:m.start(1)].strip().strip(","), m.group(1), m.group(2),
            (m.group(3) or "").strip())


def _strip_our_command(opts):
    """Remove any command="..." option (ours or a previous one), keep the rest."""
    o = re.sub(r'(?:^|,)\s*command="[^"]*"', "", opts or "")
    o = re.sub(r",\s*,", ",", o).strip()
    return o.strip(",")


def _sandbox_option(email):
    return 'command="%s %s"' % (SESSION_SH, email)


def sync_authorized_key_modes():
    """Rewrite authorized_keys so every key gets the session mode of its
    e-mail: sandboxed keys run through ggw-session, 'full' keys get a normal
    login shell. Preserves other options and the key itself. A key that already
    carries a command= from ANOTHER tool is left untouched (like a custom hook)."""
    if not os.path.isfile(SSH_KEYS):
        return 0
    lines = open(SSH_KEYS, encoding="utf-8", errors="ignore").read().splitlines()
    out, changed = [], 0
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            out.append(line)
            continue
        parts = _split_key_line(s)
        if not parts:
            out.append(line)
            continue
        opts, ktype, b64, comment = parts
        foreign = re.search(r'(?:^|,)\s*command="([^"]*)"', opts)
        if foreign and SESSION_SH not in foreign.group(1):
            out.append(line)          # another tool owns this key — do not touch
            continue
        emails = [e.lower() for e in EMAIL_RE.findall(s)]
        email = emails[0] if emails else ""
        base = _strip_our_command(opts)
        if email and ssh_mode_of(email) == "sandbox":
            new_opts = (base + "," if base else "") + _sandbox_option(email)
        else:
            new_opts = base
        new_line = ((new_opts + " ") if new_opts else "") + ktype + " " + b64 + \
                   ((" " + comment) if comment else "")
        if new_line != s:
            changed += 1
        out.append(new_line)
    if changed:
        _backup_authorized_keys()
        with LOCK:
            open(SSH_KEYS, "w", encoding="utf-8", newline="\n").write(
                "\n".join(out) + ("\n" if out else ""))
        try:
            os.chmod(SSH_KEYS, 0o600)
        except Exception:
            pass
    return changed


# --------------------------------------------------------------------------
# Git command safety for the GUI runner
# --------------------------------------------------------------------------
COMMANDS = [
    ("status",   "Show status",            False),
    ("log",      "Commit history",         False),
    ("blame",    "Who wrote each line",    False),
    ("diff",     "Show diff",              False),
    ("show",     "Show one commit",        False),
    ("add",      "Stage files",            False),
    ("commit",   "Commit staged changes",  True),
    ("restore",  "Discard changes",        True),
    ("stash",    "Stash push / pop / list", True),
    ("branch",   "List / create branch",   False),
    ("switch",   "Switch branch",          True),
    ("checkout", "Checkout branch / file", True),
    ("merge",    "Merge a branch",         True),
    ("rebase",   "Rebase a branch",        True),
    ("cherry-pick", "Apply a commit onto this branch", True),
    ("tag",      "List / create tags",     False),
    ("describe", "Describe nearest tag",   False),
    ("fetch",    "Fetch from remote",      True),
    ("pull",     "Pull",                   True),
    ("push",     "Push",                   True),
]
ALLOWED_CMDS  = {c for c, _, _ in COMMANDS}
NEEDS_CONFIRM = {c for c, _, n in COMMANDS if n}

BLOCK_RE = re.compile(
    r"upload[-_]pack|receive[-_]pack|proxy|exec|alias\.|core\.|"
    r"--git-dir|--work-tree|--namespace|--config", re.I)
URLISH_RE = re.compile(r"//|\w+@[A-Za-z0-9.-]+:")


def guard_args(cmd, args_text):
    if cmd not in ALLOWED_CMDS:
        abort(400, "Command not allowed: %s" % cmd)
    try:
        args = shlex.split(args_text or "")
    except ValueError as e:
        abort(400, "Bad arguments: %s" % e)
    out, free_text_next = [], False
    for a in args:
        if free_text_next:            # commit message: allow spaces/punctuation
            if len(a) > 400 or "\n" in a or "\r" in a or '"' in a:
                abort(400, "Unsafe commit message")
            out.append(a)
            free_text_next = False
            continue
        if a in ("-m", "-M", "--message"):
            out.append(a)
            free_text_next = True
            continue
        if len(a) > 300 or BLOCK_RE.search(a) or a in ("-c", "--exec"):
            abort(400, "Argument not permitted: %s" % a[:60])
        if URLISH_RE.search(a):
            abort(400, "Use the configured remote (e.g. 'origin'), not a URL.")
        out.append(a)
    return out


def set_last_output(label, ok, text):
    session["last_out"] = {"label": label, "ok": ok, "text": text[-8000:]}


def pop_last_output():
    return session.pop("last_out", None)


# --------------------------------------------------------------------------
# Flask app
# --------------------------------------------------------------------------
app = Flask(__name__)


def _load_secret():
    app.config["SECRET_KEY"] = cfg_get("secret") or secrets.token_hex(32)


_load_secret()


def csrf_field():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return markupsafe.Markup(
        '<input type="hidden" name="csrf" value="%s">' % session["_csrf"])


app.jinja_env.globals["csrf_field"] = csrf_field


@app.before_request
def gate():
    public = request.endpoint in {"setup", "login", "static", "logout"}

    # CSRF on every POST (public and protected)
    if request.method == "POST" and request.endpoint != "logout":
        tok = request.form.get("csrf") or request.headers.get("X-CSRF") or ""
        if not hmac.compare_digest(tok, session.get("_csrf", "")):
            abort(400, "CSRF check failed")

    if public:
        if request.endpoint == "setup" and gui_users():
            return redirect(url_for("login"))
        return None

    migrate_legacy_admin_password()
    if not gui_users():
        return redirect(url_for("setup"))
    if not session.get("user"):
        # preserve the full URL (path + query) so deep links survive login
        target = request.path
        if request.query_string:
            target += "?" + request.query_string.decode("utf-8", "replace")
        return redirect(url_for("login", next=target))


# ---------------------- auth ----------------------
@app.route("/setup", methods=["GET", "POST"])
def setup():
    if gui_users():
        return redirect(url_for("login"))
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        pw = request.form.get("pw", "")
        if not re.match(r"^[a-zA-Z0-9_.-]{2,30}$", username):
            flash("Username: 2-30 characters (letters, digits, . _ -).", "error")
            return render_template("setup.html")
        if len(pw) < 6:
            flash("Password must be at least 6 characters.", "error")
            return render_template("setup.html")
        create_gui_user(username, pw, "admin")
        _load_secret()
        session.clear()
        session.update(user=username, role="admin")
        flash("Setup complete. Welcome to Git Gateway.", "success")
        return redirect(url_for("dashboard"))
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        pw = request.form.get("pw", "")
        u = find_gui_user(username)
        if u and hmac.compare_digest(_pw_hash(pw, u.get("salt", "")), u.get("hash", "")):
            session["user"] = username
            session["role"] = u.get("role", "viewer")
            session["_csrf"] = secrets.token_hex(16)
            nxt = request.args.get("next")
            return redirect(nxt if nxt and nxt.startswith("/") else url_for("dashboard"))
        flash("Wrong username or password.", "error")
    if not gui_users():
        return redirect(url_for("setup"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/password", methods=["POST"])
def password():
    """Change your OWN password."""
    u = find_gui_user(session.get("user", ""))
    if not u:
        flash("Account not found.", "error")
        return redirect(url_for("settings"))
    if not hmac.compare_digest(_pw_hash(request.form.get("old", ""), u["salt"]), u["hash"]):
        flash("Current password is wrong.", "error")
        return redirect(url_for("settings"))
    new = request.form.get("new", "")
    if len(new) < 6:
        flash("New password too short (min 6 chars).", "error")
        return redirect(url_for("settings"))
    users = gui_users()
    for x in users:
        if x["username"] == u["username"]:
            x["hash"] = _pw_hash(new, x["salt"])
    save_gui_users(users)
    flash("Password changed.", "success")
    return redirect(url_for("settings"))


def admin_required(fn):
    @wraps(fn)
    def w(*a, **k):
        if session.get("role") != "admin":
            flash("Admin access only — your account is read-only.", "error")
            return redirect(url_for("dashboard"))
        return fn(*a, **k)
    return w


# ---------------------- GUI account management (admin) ----------------------
@app.route("/gui-users/add", methods=["POST"])
@admin_required
def gui_users_add():
    username = request.form.get("username", "").strip().lower()
    pw = request.form.get("pw", "")
    role = request.form.get("role", "viewer")
    if not re.match(r"^[a-zA-Z0-9_.-]{2,30}$", username):
        flash("Invalid username (2-30 chars: letters, digits, . _ -).", "error")
        return redirect(url_for("users"))
    if len(pw) < 6:
        flash("Password must be at least 6 characters.", "error")
        return redirect(url_for("users"))
    if role not in ROLES:
        role = "viewer"
    if find_gui_user(username):
        flash("Username already exists.", "error")
        return redirect(url_for("users"))
    email = (request.form.get("email") or "").strip().lower()
    if email and not EMAIL_RE.fullmatch(email):
        flash("Invalid identity e-mail.", "error")
        return redirect(url_for("users"))
    create_gui_user(username, pw, role)
    if email:
        users = gui_users()
        for u in users:
            if u["username"] == username:
                u["email"] = email
        save_gui_users(users)
    flash("Account %s created (%s)."
          % (username, role + (" — commits as %s" % email if email else "")), "success")
    return redirect(url_for("users"))


@app.route("/gui-users/del", methods=["POST"])
@admin_required
def gui_users_del():
    username = request.form.get("username", "").strip()
    if username == session.get("user"):
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("users"))
    users = [u for u in gui_users() if u.get("username") != username]
    if not any(u.get("role") == "admin" for u in users):
        flash("Cannot remove the last admin account.", "error")
        return redirect(url_for("users"))
    if len(users) == len(gui_users()):
        flash("Account not found.", "error")
        return redirect(url_for("users"))
    save_gui_users(users)
    flash("Account %s deleted." % username, "success")
    return redirect(url_for("users"))


@app.route("/gui-users/link", methods=["POST"])
@admin_required
def gui_users_link():
    """Link (or clear) the SSH identity e-mail of a GUI account, so commits
    made by that account through the panel are stamped with THIS identity."""
    username = request.form.get("username", "").strip()
    email    = (request.form.get("email") or "").strip().lower()
    users = gui_users()
    for u in users:
        if u.get("username") == username:
            if email and not EMAIL_RE.fullmatch(email):
                flash("Invalid e-mail address.", "error")
                return redirect(url_for("users"))
            u["email"] = email or None
            save_gui_users(users)
            flash("%s now commits as %s via the panel%s."
                  % (username, email or "(no identity — commits refused)",
                     "" if email else " — link an e-mail to enable 'git commit'"),
                  "success")
            return redirect(url_for("users"))
    flash("Account not found.", "error")
    return redirect(url_for("users"))


@app.route("/gui-users/reset", methods=["POST"])
@admin_required
def gui_users_reset():
    username = request.form.get("username", "").strip()
    new = request.form.get("new", "")
    if len(new) < 6:
        flash("Password too short (min 6 chars).", "error")
        return redirect(url_for("users"))
    users = gui_users()
    for x in users:
        if x.get("username") == username:
            x["hash"] = _pw_hash(new, x["salt"])
            save_gui_users(users)
            flash("Password of %s reset." % username, "success")
            return redirect(url_for("users"))
    flash("Account not found.", "error")
    return redirect(url_for("users"))


# ---------------------- dashboard ----------------------
@app.route("/")
def dashboard():
    st = state_get()
    repos = []
    for p in find_repos():
        r = repo_meta(p)
        r["hook"]  = hook_state(p, st)
        r["users"] = st["allowed"].get(p, [])
        repos.append(r)

    feed = []
    for r in repos:
        lg = run(["git", "log", "-6", "--pretty=format:%at\x1f%an\x1f%ae\x1f%H\x1f%s"],
                 cwd=r["path"], timeout=20)
        for line in lg["out"].splitlines():
            p = line.split("\x1f")
            if len(p) == 5:
                feed.append({"repo": r["name"], "path": r["path"], "author": p[1],
                             "email": p[2], "hash": p[3][:8], "hash_full": p[3],
                             "msg": p[4], "when": rel_time(p[0]), "ts": int(p[0])})
    feed.sort(key=lambda x: -x["ts"])

    return render_template("dashboard.html", repos=repos, feed=feed[:40],
                           output=pop_last_output(),
                           total=len(repos), people=len(all_emails()),
                           **base_ctx())


@app.route("/scan", methods=["POST"])
@admin_required
def scan():
    found = find_repos()
    st = state_get()
    for p in list(st["allowed"]):
        if p not in found and not os.path.isdir(p):
            del st["allowed"][p]
    state_set(st)
    n = refresh_hooks()
    flash("Rescan complete: %d repositories found. Hooks refreshed on %d." % (len(found), n), "success")
    return redirect(url_for("dashboard"))


@app.route("/hooks/refresh", methods=["POST"])
@admin_required
def hooks_refresh():
    n = refresh_hooks()
    flash("Hooks refreshed on %d repositories." % n, "success")
    return redirect(url_for("dashboard"))


@app.route("/hook/install", methods=["POST"])
@admin_required
def hook_install():
    repo = request.form.get("repo", "")
    if repo not in find_repos():
        flash("Repository not found — cannot install the hook.", "error")
        return redirect(url_for("dashboard"))
    st = state_get()
    install_hook(repo, st["allowed"].get(repo, []))
    nxt = request.form.get("next") or url_for("dashboard")
    flash("Hook written for %s." % os.path.basename(repo), "success")
    return redirect(nxt)


@app.route("/hook/remove", methods=["POST"])
@admin_required
def hook_remove():
    """Delete our hook files (.ggw-verify / pre-commit / post-commit) — only
    if they are ours or broken/empty. A real custom hook written by other
    tooling is never removed."""
    repo = request.form.get("repo", "")
    nxt  = request.form.get("next") or url_for("dashboard")
    if repo not in find_repos():
        flash("Repository not found — cannot remove the hook.", "error")
        return redirect(url_for("dashboard"))
    removed, refused = [], False
    for name in ("pre-commit", "post-commit"):
        hook = os.path.join(repo, ".git", "hooks", name)
        if not os.path.isfile(hook):
            continue
        try:
            content = open(hook, encoding="utf-8", errors="ignore").read()
        except Exception:
            content = ""
        if HOOK_MARKER not in content and content.strip():
            refused = True                 # a real custom hook — never delete
        else:
            os.remove(hook)
            removed.append(name)
    verify = os.path.join(repo, ".git", "hooks", ".ggw-verify")
    if os.path.isfile(verify):
        os.remove(verify)                  # shared verifier is always ours
    if refused and not removed:
        flash("These are custom hooks (not written by Git Gateway) — removing "
              "them is refused. Remove them manually if you are sure.", "error")
        return redirect(nxt)
    if not removed:
        flash("No Git Gateway hook present on %s." % os.path.basename(repo), "info")
        return redirect(nxt)
    flash("Git Gateway hooks removed from %s. Commits are no longer blocked "
          "here (the allowlist file was left in place)."
          % os.path.basename(repo), "success")
    return redirect(nxt)


@app.route("/bashrc/install", methods=["POST"])
@admin_required
def bashrc_install():
    install_bashrc_block()
    flash("Identity script written and the .bashrc block installed. "
          "New SSH sessions will automatically stamp commits with the "
          "logged-in user's name & e-mail.", "success")
    return redirect(url_for("settings") if request.form.get("next") == "settings"
                    else url_for("dashboard"))


# ---------------------- users & keys ----------------------
@app.route("/users")
def users():
    st = state_get()
    keys = parse_authorized_keys()
    ssh_set = ssh_emails()
    modes = cfg_get("ssh_modes") or {}
    rows = []
    for em in sorted(ssh_set | set(st["manual_emails"])):
        mine = [k for k in keys if em in k["emails"]]
        rows.append({
            "email": em,
            "name": display_name_of(em, st),
            "has_key": em in ssh_set,
            "mode": "full" if modes.get(em) == "full" else "sandbox",
            "fingerprints": [k["fingerprints"] or "— (fingerprint unavailable)" for k in mine] or [],
            "comment": mine[0]["comment"] if mine else "",
            "repos": [os.path.basename(p) for p, lst in st["allowed"].items() if em in lst],
            "repos_num": sum(1 for lst in st["allowed"].values() if em in lst),
        })
    return render_template("users.html", rows=rows, keys=keys,
                           insecure_keys=sum(1 for k in keys if not k["secure"]),
                           sandbox=sandbox_status(), **base_ctx())


@app.route("/users/add", methods=["POST"])
@admin_required
def users_add():
    em = request.form.get("email", "").strip().lower()
    if not EMAIL_RE.fullmatch(em):
        flash("Invalid e-mail address.", "error")
        return redirect(url_for("users"))
    st = state_get()
    if em not in st["manual_emails"] and em not in ssh_emails():
        st["manual_emails"].append(em)
        state_set(st)
        refresh_hooks()
    flash("User %s added. Now grant repositories on the Permissions page." % em, "success")
    return redirect(url_for("users"))


@app.route("/users/name", methods=["POST"])
@admin_required
def users_name():
    em, name = request.form.get("email", "").strip(), request.form.get("name", "").strip()
    st = state_get()
    if name:
        st["display_names"][em] = name
    else:
        st["display_names"].pop(em, None)
    if em not in ssh_emails() and em not in st["manual_emails"]:
        st["manual_emails"].append(em)
    state_set(st)
    refresh_hooks()
    flash("Saved.", "success")
    return redirect(url_for("users"))


@app.route("/users/del", methods=["POST"])
@admin_required
def users_del():
    em = request.form.get("email", "").strip()
    st = state_get()
    st["manual_emails"] = [e for e in st["manual_emails"] if e != em]
    st["display_names"].pop(em, None)
    for repo in list(st["allowed"]):
        st["allowed"][repo] = [e for e in st["allowed"][repo] if e != em]
    state_set(st)
    refresh_hooks()
    flash("User %s removed everywhere; hooks updated." % em, "success")
    return redirect(url_for("users"))


# ---------------------- authorized_keys management ----------------------


def _backup_authorized_keys():
    """Keep one backup copy before every write, so mistakes are reversible."""
    try:
        import shutil
        shutil.copy2(SSH_KEYS, SSH_KEYS + ".ggw-bak")
        return True
    except Exception:
        return False


@app.route("/keys/add", methods=["POST"])
@admin_required
def keys_add():
    body = (request.form.get("key") or "").strip()
    extra_email = (request.form.get("email") or "").strip().lower()
    if not body:
        flash("Paste the public key first.", "error")
        return redirect(url_for("users"))
    if "PRIVATE KEY" in body or body.startswith("-----"):
        flash("That is a PRIVATE key — never paste it anywhere! "
              "Paste the .pub (public) key file contents.", "error")
        return redirect(url_for("users"))
    body = " ".join(body.split())                       # unwrap paste artifacts
    m = re.match(r"^(?:\S+=(?:\"[^\"]*\"|\S+) )*(" + KEY_TYPE_RE + r") ([A-Za-z0-9+/=]{40,})\s*(.*)$", body)
    if not m:
        flash("That does not look like a valid public key "
              "(expected: ssh-ed25519 / ssh-rsa / ecdsa… then the key base64).", "error")
        return redirect(url_for("users"))
    ktype, b64, comment = m.group(1), m.group(2), (m.group(3) or "").strip()
    if re.search(KEY_TYPE_RE, comment):
        flash("One key at a time please — that paste contained more than one key.", "error")
        return redirect(url_for("users"))
    email = (EMAIL_RE.findall(comment) or ([extra_email] if EMAIL_RE.fullmatch(extra_email or "") else []))
    if not email:
        flash("The key comment must contain your work e-mail "
              '(like ssh-keygen -C "name@company.com") — or type it in the e-mail box below the field.',
              "error")
        return redirect(url_for("users"))
    if EMAIL_RE.fullmatch(extra_email or "") and not EMAIL_RE.search(comment):
        comment = extra_email              # add the e-mail as the key comment

    ssh_dir = os.path.dirname(SSH_KEYS)
    os.makedirs(ssh_dir, exist_ok=True)
    line = body
    try:
        os.chmod(ssh_dir, 0o700)
    except Exception:
        pass
    _backup_authorized_keys()
    if os.path.isfile(SSH_KEYS):
        existing = open(SSH_KEYS, encoding="utf-8", errors="ignore").read()
        if b64 in existing:
            flash("This exact key is already in authorized_keys.", "info")
            return redirect(url_for("users"))
        line = existing.rstrip("\n") + "\n" + body
    with LOCK:
        open(SSH_KEYS, "w", encoding="utf-8", newline="\n").write(line + "\n")
    try:
        os.chmod(SSH_KEYS, 0o600)
    except Exception:
        pass
    flash("Key added (%s). Its e-mail %s appears on the Users page right away; "
          "press Rescan applications so repositories see it too. "
          "A backup of the previous file was saved as authorized_keys.ggw-bak."
          % (ktype, email[0]), "success")
    if cfg_get("sandbox_enabled"):
        sync_authorized_key_modes()
    return redirect(url_for("users"))


@app.route("/keys/del", methods=["POST"])
@admin_required
def keys_del():
    try:
        idx = int(request.form.get("index", ""))
    except ValueError:
        abort(400, "Bad key index")
    if not os.path.isfile(SSH_KEYS):
        flash("No authorized_keys file.", "error")
        return redirect(url_for("users"))
    lines = open(SSH_KEYS, encoding="utf-8", errors="ignore").read().splitlines()
    expect = (request.form.get("expect") or "").strip()
    if idx < 0 or idx >= len(lines) or not lines[idx].strip() or lines[idx].strip().startswith("#") \
       or (expect and lines[idx].strip() != expect):
        flash("Key changed on disk — refresh the page and try again.", "error")
        return redirect(url_for("users"))
    _backup_authorized_keys()
    with LOCK:
        new = [l for i, l in enumerate(lines) if i != idx]
        open(SSH_KEYS, "w", encoding="utf-8", newline="\n").write("\n".join(new) + ("\n" if new else ""))
    flash("Key line %d removed (backup saved as authorized_keys.ggw-bak). "
          "Its e-mail no longer comes from SSH; if it was granted repositories, "
          "its access remains until you untick it on the Permissions page."
          % idx, "success")
    return redirect(url_for("users"))


@app.route("/ssh/mode", methods=["POST"])
@admin_required
def ssh_mode():
    """Set one e-mail's SSH session mode and rewrite its authorized_keys line."""
    email = (request.form.get("email") or "").strip().lower()
    mode  = request.form.get("mode") or "sandbox"
    if not EMAIL_RE.fullmatch(email):
        flash("Invalid e-mail address.", "error")
        return redirect(url_for("users"))
    if mode not in ("sandbox", "full"):
        abort(400, "Bad SSH mode")
    modes = dict(cfg_get("ssh_modes") or {})
    modes[email] = mode
    cfg_set(ssh_modes=modes)
    changed = sync_authorized_key_modes()
    if mode == "sandbox":
        flash("%s now gets a SECURE SSH session: only its granted applications "
              "are visible, the rest of the server is hidden by the kernel "
              "(authorized_keys updated%s)." %
              (email, ", %d key line(s) rewritten" % changed if changed else ""),
              "success")
    else:
        flash("%s now gets a FULL login shell (no sandbox). Only give this to "
              "the server administrator." % email, "warning")
    return redirect(url_for("users"))


@app.route("/ssh/apply", methods=["POST"])
@admin_required
def ssh_apply():
    """Install the session script and (re)write every sandboxed key line."""
    install_session_script()
    changed = sync_authorized_key_modes()
    ready = sandbox_status()
    if not ready["bwrap"]:
        flash("Session script written, but bubblewrap is NOT installed on this "
              "server — sandboxed keys cannot connect until you run "
              "'sudo apt install bubblewrap'.", "error")
    else:
        flash("Session script installed; %d authorized_keys line(s) updated. "
              "New SSH sessions are isolated per key." % changed, "success")
    return redirect(url_for("users"))


@app.route("/ssh/toggle", methods=["POST"])
@admin_required
def ssh_toggle():
    enabled = request.form.get("enabled") == "1"
    ready = sandbox_status()
    if enabled and not (ready["bwrap"] and ready["userns"]):
        flash("Cannot enable secure SSH sessions: %s" %
              ("bubblewrap is not installed (sudo apt install bubblewrap)."
               if not ready["bwrap"] else
               "unprivileged user namespaces are disabled on this kernel."),
              "error")
        return redirect(url_for("users"))
    cfg_set(sandbox_enabled=enabled)
    changed = 0
    if enabled:
        install_session_script()
        changed = sync_authorized_key_modes()
    flash(("Secure SSH sessions ENABLED — %d key line(s) rewritten. "
           "Test with a developer key before announcing it." % changed)
          if enabled else
          "Secure SSH sessions DISABLED — sandboxed keys cannot connect "
          "(re-enable here).", "success" if enabled else "info")
    return redirect(url_for("users"))


# ---------------------- permissions matrix ----------------------
@app.route("/permissions")
def permissions():
    st = state_get()
    repos = []
    for p in find_repos():
        r = repo_meta(p)
        r["hook"] = hook_state(p, st)
        repos.append(r)
    return render_template("permissions.html", repos=repos, emails=all_emails(),
                           allowed=st["allowed"], ssh_email_set=ssh_emails(),
                           **base_ctx())


@app.route("/permissions/save", methods=["POST"])
@admin_required
def permissions_save():
    st, emails, changed = state_get(), all_emails(), 0
    for repo in find_repos():
        selected = [e for e in emails if request.form.get("%s|%s" % (repo, e))]
        if selected != st["allowed"].get(repo):
            st["allowed"][repo] = selected
            changed += 1
            install_hook(repo, selected)
    state_set(st)
    flash("Permissions saved. Hooks updated on %d changed repositories." % changed, "success")
    return redirect(url_for("permissions"))


# ---------------------- repository detail ----------------------
@app.route("/repo")
def repo():
    path = request.args.get("p", "")
    if path not in find_repos():
        flash("Repository not found (it may have been moved or removed). "
              "Press Rescan applications to re-detect it.", "error")
        return redirect(url_for("dashboard"))
    st = state_get()
    r = repo_meta(path)
    r["hook"], r["users"] = hook_state(path, st), st["allowed"].get(path, [])

    commits = []
    for line in run(["git", "log", "-100", "--pretty=format:%at\x1f%ct\x1f%an\x1f%ae\x1f%H\x1f%s"],
                    cwd=path, timeout=30)["out"].splitlines():
        p = line.split("\x1f")
        if len(p) == 6:
            commits.append({
                "when": rel_time(p[0]),
                "date": datetime.datetime.fromtimestamp(int(p[0])).strftime("%Y-%m-%d %H:%M"),
                "author": p[2], "email": p[3],
                "hash": p[4][:8], "hash_full": p[4], "msg": p[5], "ts": int(p[0])})

    statuses = run(["git", "status", "--porcelain"], cwd=path)["out"].splitlines()

    branches, remotes = [], []
    for line in run(["git", "branch", "-vv"], cwd=path)["out"].splitlines():
        line = line.strip()
        if not line:
            continue
        current = line.startswith("*")
        line = line.lstrip("* ").strip()
        m = re.search(r"\[([^\]]+)\]", line)
        tracking = m.group(1) if m else ""
        note = line.split("]", 1)[-1].strip() if m else ""
        parts = line.split()
        h = parts[1] if len(parts) > 1 and re.match(r"^[0-9a-f]{7,40}$", parts[1]) else ""
        branches.append({"current": current, "name": parts[0], "head": h,
                         "tracking": tracking, "note": note})
    for line in run(["git", "remote", "-v"], cwd=path)["out"].splitlines():
        parts = line.split()
        if len(parts) >= 2:
            remotes.append({"name": parts[0], "url": parts[1],
                            "dir": parts[2].strip("()") if len(parts) > 2 else ""})
    diffstat = run(["git", "diff", "--stat"], cwd=path)

    return render_template("repo.html", r=r, commits=commits, statuses=statuses,
                           branches=branches, remotes=remotes,
                           diffstat=diffstat, commands=COMMANDS,
                           emails=email_rows_for(path, st), output=pop_last_output(),
                           **base_ctx())


def email_rows_for(path, st):
    ssh_set = ssh_emails()
    rows = []
    for em in sorted(ssh_set | set(st["manual_emails"])):
        has = em in st["allowed"].get(path, [])
        rows.append({"email": em, "name": display_name_of(em, st),
                     "allowed": has, "has_key": em in ssh_set})
    return rows


# commands a read-only (viewer) account may run
VIEWER_OK = {"status", "log", "blame", "diff", "show", "branch", "describe"}


@app.route("/repo/run", methods=["POST"])
def repo_run():
    path = request.form.get("repo", "")
    cmd  = (request.form.get("cmd") or "").strip()
    nxt  = request.form.get("next") or url_for("dashboard")
    if path not in find_repos():
        flash("Repository not found — cannot run 'git %s' on it." % cmd, "error")
        return redirect(url_for("dashboard"))
    if cmd not in ALLOWED_CMDS:
        abort(400, "Command not allowed: %s" % cmd)
    if session.get("role") != "admin" and cmd not in VIEWER_OK:
        flash("Your account is read-only: 'git %s' is not allowed." % cmd, "error")
        return redirect(nxt)
    if cmd in NEEDS_CONFIRM and request.form.get("confirm") != "yes":
        flash("This action needs the confirm checkbox.", "error")
        return redirect(nxt)
    args = guard_args(cmd, request.form.get("args", ""))
    extra_env = None
    if cmd == "commit":
        u = find_gui_user(session.get("user", ""))
        ident = (u or {}).get("email", "")
        if ident:
            extra_env = {"GIT_GGW_PANEL_EMAIL": ident,
                         "GIT_GGW_PANEL_NAME": ident.split("@")[0].replace(".", " ").replace("_", " ").title()}
        else:
            flash("This panel account has no developer e-mail linked "
                  "(Users & Keys → GUI accounts → Identity), so 'git commit' "
                  "will be refused by the hook.", "info")
    res = run(["git", cmd] + args, cwd=path, timeout=180, extra_env=extra_env)
    label = ("git %s %s" % (cmd, " ".join(args))).strip()
    if res["ok"]:
        flash("✓ %s" % label, "success")
    else:
        flash("✕ %s" % label, "error")
    set_last_output(label, res["ok"], res["err"] if not res["ok"] and not res["out"] else res["out"] + res["err"])
    return redirect(nxt)


@app.route("/repo/grant", methods=["POST"])
@admin_required
def repo_grant():
    """Quick toggle of one user on one repository."""
    path, email = request.form.get("repo", ""), request.form.get("email", "")
    nxt = request.form.get("next") or url_for("repo", p=path)
    if path not in find_repos() or email not in all_emails():
        flash("Repository or user not found — permission not changed.", "error")
        return redirect(url_for("dashboard"))
    st = state_get()
    lst = st["allowed"].setdefault(path, [])
    if email in lst:
        lst.remove(email)
        flash("Revoked %s on %s." % (email, os.path.basename(path)), "success")
    else:
        lst.append(email)
        flash("Granted %s on %s." % (email, os.path.basename(path)), "success")
    state_set(st)
    install_hook(path, lst)
    return redirect(nxt)


def running_port():
    """The port the process actually started on, tracked at boot."""
    return cfg_get("running_port") or cfg_get("port") or 8555


# ---------------------- service restart (requires the sudoers rule from install.sh) ----------------------
SERVICE_UNIT = "git-gateway.service"


def service_is_active():
    r = run(["systemctl", "is-active", "--quiet", SERVICE_UNIT], timeout=10)
    return r["code"] == 0


@app.route("/service/restart", methods=["POST"])
@admin_required
def service_restart():
    nxt = request.form.get("next") or url_for("settings")
    flash("Restarting the service at %s to apply the new port..." %
          datetime.fromtimestamp(time.time() + 2).strftime("%H:%M:%S"), "success")
    def _restart():
        time.sleep(2)
        run(["sudo", "-n", "systemctl", "restart", SERVICE_UNIT], timeout=60)
    threading.Thread(target=_restart, daemon=True).start()
    return redirect(nxt)


# ---------------------- settings ----------------------
@app.route("/settings")
def settings():
    run_port = running_port()
    return render_template("settings.html",
                           scan_roots="\n".join(cfg_get("scan_roots")),
                           port=cfg_get("port"),
                           run_port=run_port,
                           service_active=service_is_active(),
                           port_dirty=(str(cfg_get("port")) != str(run_port)),
                           identify=IDENTIFY_SH_BODY if os.path.isfile(IDENTIFY_SH) else None,
                           **base_ctx())


@app.route("/settings/save", methods=["POST"])
@admin_required
def settings_save():
    roots = [os.path.expanduser(r.strip()) for r in
             request.form.get("scan_roots", "").splitlines() if r.strip()]
    if roots:
        cfg_set(scan_roots=roots)
    try:
        port = int(request.form.get("port") or 0)
        if 1 <= port <= 65535:
            cfg_set(port=port)
    except ValueError:
        pass
    run_port = running_port()
    if str(cfg_get("port")) != str(run_port):
        flash("Saved. The service is still on port %s — press 'Restart service' below "
              "to switch to port %s." % (run_port, cfg_get("port")), "success")
    else:
        flash("Settings saved.", "success")
    return redirect(url_for("settings"))


def base_ctx():
    st = state_get()
    return {"emails_total": len(all_emails()),
            "email_list": sorted(all_emails()),
            "key_status": "found" if os.path.isfile(SSH_KEYS) else "missing",
            "bashrc_state": bashrc_status(),
            "ssh_path": SSH_KEYS,
            "data_dir": DATA_DIR,
            "me": session.get("user"),
            "me_role": session.get("role", "viewer"),
            "gui_users_list": gui_users() if session.get("role") == "admin" else [],
            "viewer_ok": sorted(VIEWER_OK)}


if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    port = os.environ.get("GITGATEWAY_PORT") or cfg_get("port") or 8555
    port = int(port)
    cfg_set(running_port=port)
    print(" * Git Gateway listening on 0.0.0.0:%s" % port)
    app.run(host="0.0.0.0", port=port, debug=False)
