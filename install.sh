#!/bin/bash
# ============================================================================
# Git Gateway installer — Linux server
# Installs a web app that controls:
#   * which SSH e-mail may commit to which git repository
#   * automatic committer identity on SSH login
#   * commit enforcement + git control via a web GUI (English)
#
# Usage:
#   sudo-less install:      bash install.sh
#   choose the port:        bash install.sh 8900
#   (or answer the prompt when asked)
#
# Runs as a systemd service that starts on boot and stays running.
# ============================================================================
set -e

# --- configuration ----------------------------------------------------------
DEST="$HOME/.gitgateway/app"
SERVICE_USER="$(id -un)"
SERVICE_UNIT="git-gateway.service"

# --- port: argument > prompt > default --------------------------------------
SERVICE_PORT="${1:-}"
if [ -n "$1" ] && [ "$1" != "${1//[!0-9]/}" ]; then
  echo "ERROR: port must be a number. Usage: bash install.sh [port]"; exit 1
fi
if [ -z "$SERVICE_PORT" ]; then
  read -r -p "Port for the Git Gateway web GUI [8555]: " ANSWER
  SERVICE_PORT="${ANSWER:-8555}"
fi
case "$SERVICE_PORT" in (*[!0-9]*|'') echo "ERROR: invalid port"; exit 1;; esac
if [ "$SERVICE_PORT" -lt 1 ] || [ "$SERVICE_PORT" -gt 65535 ]; then
  echo "ERROR: port out of range"; exit 1
fi

echo "==> Git Gateway installer (port $SERVICE_PORT, user $SERVICE_USER)"

# --- prerequisites ----------------------------------------------------------
command -v git >/dev/null 2>&1 || { echo "ERROR: git is not installed"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is not installed"; exit 1; }

# --- pick ONE python and stick with it everywhere ---------------------------
# (pip3 may belong to a different Python version than `python3` — that would
#  install Flask where the app can never find it. So we always install with
#  the very interpreter that will run the app.)
PYTHON_BIN="$(command -v python3)"
PYVER="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
echo "==> Using interpreter: $PYTHON_BIN (Python $PYVER)"

# sanity: pip must import? pip module must even exist for this interpreter
check_flask () { "$PYTHON_BIN" -c "import flask" >/dev/null 2>&1; }

if ! check_flask; then
  echo "==> Installing Flask with $PYTHON_BIN -m pip (user install)..."
  if ! "$PYTHON_BIN" -m pip install --user flask 2>/dev/null; then
    # pip module itself might be missing for this interpreter
    "$PYTHON_BIN" -m ensurepip --user >/dev/null 2>&1 || true
    "$PYTHON_BIN" -m pip install --user flask 2>/dev/null || pip3 install --user flask 2>/dev/null || true
  fi
fi

if ! check_flask; then
  echo "==> pip failed — falling back to a virtualenv at ~/.gitgateway/venv"
  "$PYTHON_BIN" -m venv "$HOME/.gitgateway/venv" || {
    echo "ERROR: 'python3 -m venv' failed. Run: sudo apt install python3-venv python3-pip"; exit 1; }
  "$HOME/.gitgateway/venv/bin/pip" install flask
  PYTHON_BIN="$HOME/.gitgateway/venv/bin/python"
fi

check_flask || {
  echo "ERROR: Flask could not be installed for $PYTHON_BIN."
  echo "Try: sudo apt install python3-flask python3-pip ; then re-run install.sh"
  exit 1
}
echo "==> Flask OK ($("$PYTHON_BIN" -c 'import flask; print(flask.__version__)'))"

# --- copy application files -------------------------------------------------
echo "==> Installing files to $DEST"
mkdir -p "$DEST"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -r "$SCRIPT_DIR"/app.py "$SCRIPT_DIR"/templates "$SCRIPT_DIR"/static "$DEST"/

# --- systemd service (starts on boot, stays running) ------------------------
if command -v systemctl >/dev/null 2>&1 && [ -d "/etc/systemd/system" ]; then
  echo "==> Creating systemd service $SERVICE_UNIT"
  sudo tee "/etc/systemd/system/$SERVICE_UNIT" >/dev/null <<EOF
[Unit]
Description=Git Gateway - SSH-identity controlled git access GUI
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$DEST
ExecStart=$PYTHON_BIN $DEST/app.py
Environment=GITGATEWAY_PORT=$SERVICE_PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  # allow the admin to restart the service from the GUI without a password
  echo "==> Sudoers rule (only for this service, so the GUI 'Restart service' button works)"
  sudo bash -c "echo '$SERVICE_USER ALL=(root) NOPASSWD: /usr/bin/systemctl restart $SERVICE_UNIT, /usr/bin/systemctl status $SERVICE_UNIT' > /etc/sudoers.d/git-gateway-restart"
  sudo chmod 440 /etc/sudoers.d/git-gateway-restart
  sudo visudo -c >/dev/null 2>&1 || echo "WARNING: sudoers check failed — inspect /etc/sudoers.d/git-gateway-restart"

  sudo systemctl daemon-reload
  sudo systemctl enable --now "$SERVICE_UNIT"
  sleep 1
  if sudo systemctl is-active --quiet "$SERVICE_UNIT"; then
    echo "==> Service is RUNNING and starts automatically on boot."
  else
    echo "WARNING: service did not start — check: journalctl -u $SERVICE_UNIT"
  fi
else
  echo "==> No systemd detected; start manually with:"
  echo "    GITGATEWAY_PORT=$SERVICE_PORT nohup $PYTHON_BIN $DEST/app.py >$HOME/.gitgateway/gateway.log 2>&1 &"
fi

echo ""
echo "=== Installed ==================================================="
echo "  URL:     http://<this-server-ip>:$SERVICE_PORT"
echo "  Port change later:  Options (Settings) -> Web port -> Restart service"
echo "  Logs:    journalctl -u $SERVICE_UNIT -f"
echo "  Stop:    sudo systemctl stop $SERVICE_UNIT    (also stops on reboot=false)"
echo "  Uninstall: bash $(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/uninstall.sh"
echo "================================================================="
