#!/bin/bash
# Update Git Gateway: copy the CURRENT directory's code into the running
# install (~/.gitgateway/app) and restart the service.
#
# Usage (on the server, from the folder you uploaded/updated):
#   cd /opt/git-gateway && bash update.sh
set -e

DEST="$HOME/.gitgateway/app"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_UNIT="git-gateway.service"
SERVICE_USER="$(id -un)"

echo "==> Updating Git Gateway from $SCRIPT_DIR"
for need in app.py templates static; do
  [ -e "$SCRIPT_DIR/$need" ] || { echo "ERROR: $SCRIPT_DIR/$need is missing"; exit 1; }
done

mkdir -p "$DEST"
cp -r "$SCRIPT_DIR"/app.py "$DEST"/
rm -rf "$DEST"/templates "$DEST"/static
cp -r "$SCRIPT_DIR"/templates "$SCRIPT_DIR"/static "$DEST"/

# --- SSH login-policy helper (root-owned, exact-argument sudoers rule) ------
# The panel's "Disable password logins" button calls this helper; it can only
# run 'status', 'disable-password' and 'enable-password' — nothing else.
if [ -f "$SCRIPT_DIR/ssh-security.sh" ]; then
  if sudo -n true 2>/dev/null || [ -t 0 ]; then
    echo "==> Installing the SSH login-policy helper (root)"
    if sudo install -m 0755 -o root -g root "$SCRIPT_DIR/ssh-security.sh" /usr/local/sbin/git-gateway-ssh; then
      RULE="$SERVICE_USER ALL=(root) NOPASSWD: /usr/local/sbin/git-gateway-ssh status, /usr/local/sbin/git-gateway-ssh disable-password, /usr/local/sbin/git-gateway-ssh enable-password"
      sudo bash -c "echo '$RULE' > /etc/sudoers.d/git-gateway-ssh"
      sudo chmod 440 /etc/sudoers.d/git-gateway-ssh
      sudo visudo -c >/dev/null 2>&1 || echo "WARNING: sudoers check failed - inspect /etc/sudoers.d/git-gateway-ssh"
      echo "==> Helper ready: /usr/local/sbin/git-gateway-ssh"
    else
      echo "WARNING: could not install /usr/local/sbin/git-gateway-ssh (continuing)"
    fi
  else
    echo "==> SSH login-policy helper NOT installed (no interactive sudo here)."
    echo "    Run these two lines once, then reload Settings in the panel:"
    echo "      sudo install -m 0755 -o root -g root '$SCRIPT_DIR/ssh-security.sh' /usr/local/sbin/git-gateway-ssh"
    echo "      sudo bash -c \"echo '$SERVICE_USER ALL=(root) NOPASSWD: /usr/local/sbin/git-gateway-ssh status, /usr/local/sbin/git-gateway-ssh disable-password, /usr/local/sbin/git-gateway-ssh enable-password' > /etc/sudoers.d/git-gateway-ssh && chmod 440 /etc/sudoers.d/git-gateway-ssh\""
  fi
fi

if command -v systemctl >/dev/null 2>&1; then
  if sudo -n systemctl restart "$SERVICE_UNIT" 2>/dev/null; then
    echo "==> Service restarted with the new code."
  else
    echo "==> Files copied. Restart manually: sudo systemctl restart $SERVICE_UNIT"
  fi
else
  echo "==> Files copied (no systemd). Restart the process manually."
fi

echo "==> Done. Hard-refresh the browser (Ctrl+Shift+R) to bypass CSS cache."
