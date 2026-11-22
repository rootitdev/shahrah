#!/usr/bin/env bash
# Install swap + Telegram host alerts on this VPS.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SBIN=/usr/local/sbin
ETC=/etc/shahrah

[[ "$(id -u)" -eq 0 ]] || { echo "run as root" >&2; exit 1; }

install -d -m 0755 "$SBIN"
install -m 0755 "$SCRIPT_DIR/sbin/shahrah-swap.sh" "$SBIN/shahrah-swap.sh"
install -m 0755 "$SCRIPT_DIR/sbin/shahrah-host-alert.sh" "$SBIN/shahrah-host-alert.sh"
install -m 0644 "$SCRIPT_DIR/systemd/shahrah-host-alert.service" /etc/systemd/system/
install -m 0644 "$SCRIPT_DIR/systemd/shahrah-host-alert.timer" /etc/systemd/system/

"$SBIN/shahrah-swap.sh"

if [[ ! -f "$ETC/host-alert.env" ]]; then
  install -d -m 0755 "$ETC"
  if [[ -f "$SCRIPT_DIR/examples/host-alert.env.example" ]]; then
    cp "$SCRIPT_DIR/examples/host-alert.env.example" "$ETC/host-alert.env"
    echo "Edit $ETC/host-alert.env (HOST_LABEL, SERVICES, ...)"
  fi
fi

install -d -m 0755 /var/lib/shahrah
systemctl daemon-reload
systemctl enable --now shahrah-host-alert.timer
echo "OK swap + shahrah-host-alert.timer"