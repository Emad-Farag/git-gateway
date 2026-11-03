#!/bin/bash
# ============================================================================
# Git Gateway - SSH login policy helper (root only)
#
# Installed as /usr/local/sbin/git-gateway-ssh with an exact-argument sudoers
# rule, so the panel can flip password logins on/off without a free-form sudo
# shell. Allowed commands:
#
#   git-gateway-ssh status             (read the effective sshd policy)
#   git-gateway-ssh disable-password   (key-only logins)
#   git-gateway-ssh enable-password    (password logins allowed again)
#
# Every change is validated with `sshd -t` BEFORE sshd is reloaded; a broken
# configuration is rolled back so SSH can never be left in a state that
# refuses to start.
# ============================================================================
set -u

CONF_DIR="/etc/ssh/sshd_config.d"
CONF="$CONF_DIR/99-git-gateway-hardening.conf"
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_BIN="$(command -v sshd 2>/dev/null || true)"
[ -n "$SSHD_BIN" ] || SSHD_BIN="/usr/sbin/sshd"

kv () { printf '%s=%s\n' "$1" "$2"; }

need_root () {
  if [ "$(id -u)" -ne 0 ]; then
    echo "error=This helper must run as root (use the panel button)." >&2
    kv ok no
    exit 1
  fi
}

sshd_effective () {   # sshd_effective <directive> -> value from the running config
  "$SSHD_BIN" -T 2>/dev/null | awk -v k="$1" 'tolower($1)==tolower(k) {print $2; exit}'
}

reload_ssh () {
  if command -v systemctl >/dev/null 2>&1; then
    for unit in ssh sshd; do
      if systemctl is-active --quiet "$unit" 2>/dev/null; then
        systemctl reload "$unit" 2>/dev/null && { kv reloaded "$unit"; return 0; }
      fi
    done
  fi
  # last resort: ask sshd to reload itself through its pid file
  for pid in /run/sshd.pid /var/run/sshd.pid; do
    if [ -s "$pid" ]; then
      kill -HUP "$(cat "$pid")" 2>/dev/null && { kv reloaded "pid-file"; return 0; }
    fi
  done
  return 1
}

ensure_include () {
  mkdir -p "$CONF_DIR"
  if grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONFIG" 2>/dev/null; then
    return 0
  fi
  # Include must be read BEFORE any global PasswordAuthentication line,
  # because sshd keeps the FIRST value it sees.
  cp -a "$SSHD_CONFIG" "$SSHD_CONFIG.ggw-bak"
  printf 'Include /etc/ssh/sshd_config.d/*.conf\n' > "$SSHD_CONFIG.ggw-new"
  cat "$SSHD_CONFIG" >> "$SSHD_CONFIG.ggw-new"
  mv "$SSHD_CONFIG.ggw-new" "$SSHD_CONFIG"
  kv include_added yes
}

check_config () {
  "$SSHD_BIN" -t 2>/dev/null
}

status () {
  kv helper yes
  kv config_file "$CONF"
  kv managed "$([ -f "$CONF" ] && echo yes || echo no)"
  kv passwordauthentication "$(sshd_effective PasswordAuthentication)"
  kv kbdinteractiveauthentication "$(sshd_effective KbdInteractiveAuthentication)"
  kv pubkeyauthentication "$(sshd_effective PubkeyAuthentication)"
  kv permitrootlogin "$(sshd_effective PermitRootLogin)"
  if check_config; then kv config_ok yes; else kv config_ok no; fi
  if command -v systemctl >/dev/null 2>&1; then
    kv service ssh-up "$(systemctl is-active ssh 2>/dev/null || true)"
    kv service sshd-up "$(systemctl is-active sshd 2>/dev/null || true)"
  fi
  kv ok yes
}

disable_password () {
  ensure_include
  local backup=""
  [ -f "$CONF" ] && backup="$(mktemp)"
  [ -n "$backup" ] && cp -a "$CONF" "$backup"
  cat > "$CONF" <<'EOF'
# Installed by Git Gateway - SSH password logins disabled (keys only).
# Remove this file (or press "Allow password logins" in the panel) to undo.
PasswordAuthentication no
KbdInteractiveAuthentication no
EOF
  chmod 0644 "$CONF"
  if ! check_config; then
    rm -f "$CONF"
    [ -n "$backup" ] && cp -a "$backup" "$CONF"
    [ -n "$backup" ] && rm -f "$backup"
    kv ok no
    kv error "sshd rejected the new configuration - previous state restored."
    exit 1
  fi
  [ -n "$backup" ] && rm -f "$backup"
  local eff
  eff="$(sshd_effective PasswordAuthentication)"
  if [ "$eff" != "no" ]; then
    rm -f "$CONF"
    kv ok no
    kv error "PasswordAuthentication is still '$eff' - another sshd config file overrides it."
    exit 1
  fi
  if ! reload_ssh; then
    kv warning "Configuration is valid but sshd could not be reloaded - run: sudo systemctl reload ssh"
  fi
  kv passwordauthentication "$eff"
  kv ok yes
}

enable_password () {  ensure_include
  cat > "$CONF" <<'EOF'
# Installed by Git Gateway - SSH password logins allowed again.
# Keep keys-only for maximum safety: press "Disable password logins".
PasswordAuthentication yes
KbdInteractiveAuthentication yes
EOF
  chmod 0644 "$CONF"
  if ! check_config; then
    rm -f "$CONF"
    kv ok no
    kv error "sshd rejected the new configuration - this file was removed."
    exit 1
  fi
  if ! reload_ssh; then
    kv warning "Configuration is valid but sshd could not be reloaded - run: sudo systemctl reload ssh"
  fi
  kv passwordauthentication "$(sshd_effective PasswordAuthentication)"
  kv ok yes
}

case "${1:-status}" in
  status)           need_root; status ;;
  disable-password) need_root; disable_password ;;
  enable-password)  need_root; enable_password ;;
  *)
    echo "Usage: $0 {status|disable-password|enable-password}" >&2
    exit 2 ;;
esac
