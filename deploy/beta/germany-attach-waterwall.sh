#!/usr/bin/env bash
# Attach WaterWall exit leg to an existing Shahrah node (beta phase 2). Does not touch Xray state.
#
# Prereqs (standalone Shahrah exit): state.json present. For PasarGuard-owned :443 use
# panel-exit-attach-waterwall.sh instead (no state.json).
# Generates /etc/shahrah/backhaul.key on first run — copy to Iran before enabling Iran relay.
#
# Usage (on Germany exit):
#   sudo IRAN_PEER_IP=198.51.100.7 ./deploy/beta/germany-attach-waterwall.sh
# Optional: WW_TUNNEL_PORT=8443 WW_MODE=reverse COVER_ADDR=203.0.113.50
set -euo pipefail

IRAN_PEER_IP="${IRAN_PEER_IP:-}"
[[ -n "$IRAN_PEER_IP" ]] || {
  echo "set IRAN_PEER_IP to the Iran VPS public IPv4" >&2
  exit 2
}

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../install.sh
source "$DIR/../install.sh"

PANEL_OWNED="${PANEL_OWNED:-0}"
if [[ "$PANEL_OWNED" != 1 ]]; then
  [[ -f /etc/shahrah/state.json ]] || die "missing state.json — use panel-exit-attach-waterwall.sh for panel nodes"
else
  export WW_EXIT_SERVICE="${PANEL_EXIT_SERVICE:-127.0.0.1:443}"
fi
[[ "$(id -u)" -eq 0 ]] || die "run as root"

export ROLE=node WW_SIDE=exit WW_PEER="$IRAN_PEER_IP" WW_MODE="${WW_MODE:-reverse}"
export WW_TUNNEL_PORT="${WW_TUNNEL_PORT:-8443}"
export WW_COVER_SNI="${WW_COVER_SNI:-www.speedtest.net}"
export FIREWALL=0 WITH_PAQET=0 WITH_WARP=0 WITH_HY2=0
if [[ -n "${COVER_ADDR:-}" ]]; then
  export WW_COVER_ADDR="$COVER_ADDR"
fi

enforce_control_plane
install_waterwall
echo "OK WaterWall exit leg (mode=$WW_MODE tunnel=$WW_TUNNEL_PORT)"
echo "Next: copy /etc/shahrah/backhaul.key to Iran (root-only), then iran-relay-install.sh"
echo "Optional: shahrah --state /etc/shahrah/state.json client-host <IRAN_PUBLIC_IP> && apply"
