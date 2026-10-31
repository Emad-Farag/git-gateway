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
  sudo systemctl daemon-reload
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
