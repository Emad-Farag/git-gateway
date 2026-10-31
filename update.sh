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

echo "==> Updating Git Gateway from $SCRIPT_DIR"
for need in app.py templates static; do
  [ -e "$SCRIPT_DIR/$need" ] || { echo "ERROR: $SCRIPT_DIR/$need is missing"; exit 1; }
done

mkdir -p "$DEST"
cp -r "$SCRIPT_DIR"/app.py "$DEST"/
rm -rf "$DEST"/templates "$DEST"/static
cp -r "$SCRIPT_DIR"/templates "$SCRIPT_DIR"/static "$DEST"/

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
