#!/bin/bash
# Uninstall Git Gateway.
# Kept hooks + allowlists in repositories REMAIN by default so authorization
# keeps working; delete them with the printed commands when not wanted.
set -e
SERVICE_USER="$(id -un)"
SERVICE_UNIT="git-gateway.service"

if [ "$1" != "--remove-hooks" ]; then
  echo "Repository hooks keep enforcing the allowlist after uninstall."
  echo "Run with  --remove-hooks  to also delete every hook + allowlist."
fi

if command -v systemctl >/dev/null 2>&1; then
  sudo systemctl disable --now "$SERVICE_UNIT" 2>/dev/null || true
  sudo rm -f "/etc/systemd/system/$SERVICE_UNIT"
  sudo rm -f /etc/sudoers.d/git-gateway-restart
  sudo rm -f /usr/local/sbin/git-gateway-ssh /etc/sudoers.d/git-gateway-ssh
  sudo systemctl daemon-reload
fi

# A sandboxed key line points at ~/.gitgateway/ggw-session. Removing that folder
# while the forced command is still in authorized_keys would lock EVERY key out,
# so strip our launcher (and only ours) before deleting the runtime files.
if [ -f "$HOME/.ssh/authorized_keys" ]; then
  python3 - "$HOME/.ssh/authorized_keys" <<'PY'
import re, shutil, sys
p = sys.argv[1]
lines = open(p, encoding="utf-8", errors="ignore").read().splitlines()
out, changed = [], 0
for line in lines:
    if "ggw-session" in line and 'command="' in line:
        new = re.sub(r'(?:^|,)\s*command="[^"]*ggw-session[^"]*"', "", line)
        new = re.sub(r",\s*,", ",", new).strip(",")
        if new != line:
            changed += 1
        out.append(new)
    else:
        out.append(line)
if changed:
    shutil.copy2(p, p + ".ggw-bak")
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out) + "\n")
    print("removed the Git Gateway session launcher from %d key line(s)" % changed)
PY
fi

if [ "$1" == "--remove-hooks" ] && [ -f "$HOME/.gitgateway/permissions.json" ]; then
  python3 - "$HOME/.gitgateway/permissions.json" <<'PY'
import json, os, sys
st = json.load(open(sys.argv[1]))
for repo in st.get("allowed", {}):
    hooks = os.path.join(repo, ".git", "hooks")
    allow = os.path.join(hooks, ".ggw-allowed")
    hook = os.path.join(hooks, "pre-commit")
    try:
        content = open(hook, encoding="utf-8", errors="ignore").read()
    except Exception:
        content = ""
    if "Git Gateway" in content:
        os.remove(hook)
        print("removed", hook)
    if os.path.isfile(allow):
        os.remove(allow)
        print("removed", allow)
PY
fi

rm -rf "$HOME/.gitgateway"

# remove the bashrc block
sed -i '/# >>> git-gateway >>>/,/# <<< git-gateway <<</d' "$HOME/.bashrc"

echo "Git Gateway uninstalled."
echo "SSH hardening file /etc/ssh/sshd_config.d/99-git-gateway-hardening.conf was"
echo "left in place (password logins stay disabled). Remove it and reload ssh to"
echo "allow passwords again:"
echo "  sudo rm /etc/ssh/sshd_config.d/99-git-gateway-hardening.conf && sudo systemctl reload ssh"
