#!/usr/bin/env bash
# Attach WaterWall exit leg for one *named* relay peer (multi-exit). Does not rotate Xray REALITY keys.
#
# Prereqs: shahrah-xray active; /etc/shahrah/backhaul-PEER_NAME.key from Iran (same as Iran peer-add).
#
# Usage (on foreign exit):
#   sudo PEER_NAME=de IRAN_PEER_IP=<IRAN_IPV4> ./deploy/beta/exit-attach-relay-peer.sh
# Optional: USER_PORT=443 TUNNEL_PORT=8443 WW_MODE=reverse
set -euo pipefail

PEER_NAME="${PEER_NAME:-}"
IRAN_PEER_IP="${IRAN_PEER_IP:-}"
USER_PORT="${USER_PORT:-443}"
TUNNEL_PORT="${TUNNEL_PORT:-8443}"
WW_MODE="${WW_MODE:-reverse}"

[[ -n "$PEER_NAME" && -n "$IRAN_PEER_IP" ]] || {
  echo "set PEER_NAME and IRAN_PEER_IP" >&2
  exit 2
}

KEY="/etc/shahrah/backhaul-${PEER_NAME}.key"
[[ -s "$KEY" ]] || {
  echo "copy Iran's $KEY here first (see shahrah relay peer-activate HANDOFF)" >&2
  exit 2
}

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../install.sh
source "$DIR/../install.sh"

if [[ "${PANEL_OWNED:-0}" != 1 ]]; then
  [[ -f /etc/shahrah/state.json ]] || die "install exit node first or set PANEL_OWNED=1"
else
  export WW_EXIT_SERVICE="${PANEL_EXIT_SERVICE:-127.0.0.1:443}"
fi
[[ "$(id -u)" -eq 0 ]] || die "run as root"

self="$(ip -4 -o addr show dev "$(default_iface)" | awk '{split($4,a,"/"); print a[1]; exit}')"
[[ -n "$self" ]] || die "cannot detect exit public IP"

install -d -m 0750 -o root -g shahrah /etc/shahrah/waterwall/exit-"$PEER_NAME"
shahrah waterwall-config exit \
  --iran-ip "$IRAN_PEER_IP" --exit-ip "$self" \
  --key-file "$KEY" --mode "$WW_MODE" --tunnel-port "$TUNNEL_PORT" \
  --user-port "$USER_PORT" --exit-service "127.0.0.1:443" \
  --cover-sni "${WW_COVER_SNI:-www.speedtest.net}" \
  ${WW_COVER_ADDR:+--cover-addr "$WW_COVER_ADDR"} \
  --out-dir "/etc/shahrah/waterwall/exit-${PEER_NAME}"

printf '[Unit]\nDescription=shahrah WaterWall exit peer %s\nAfter=network-online.target\n\n[Service]\nWorkingDirectory=/etc/shahrah/waterwall/exit-%s\nExecStart=/usr/local/bin/waterwall -c:/etc/shahrah/waterwall/exit-%s/core.json\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n' \
  "$PEER_NAME" "$PEER_NAME" "$PEER_NAME" >"/etc/systemd/system/shahrah-waterwall-exit@${PEER_NAME}.service"

systemctl daemon-reload
systemctl enable --now "shahrah-waterwall-exit@${PEER_NAME}"

echo "OK exit WaterWall for peer=${PEER_NAME} user_port=${USER_PORT} tunnel=${TUNNEL_PORT}"
echo "Links: shahrah link USER --entry-host <IRAN_ENTRY> --entry-port ${USER_PORT}"
