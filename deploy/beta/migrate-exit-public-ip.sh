#!/usr/bin/env bash
# Re-point WaterWall after the foreign exit gets a new public IPv4 (Iran config only).
# Does not rotate REALITY keys or overwrite state.json users.
#
# On Iran (after new Germany is up with same backhaul.key):
#   sudo NEW_EXIT_IP=... IRAN_SELF_IP=... ./deploy/beta/migrate-exit-public-ip.sh
#
# On new Germany: restore bundle, re-run germany-attach-waterwall.sh with same IRAN_PEER_IP.
set -euo pipefail

NEW_EXIT_IP="${NEW_EXIT_IP:-}"
IRAN_SELF_IP="${IRAN_SELF_IP:-}"
[[ -n "$NEW_EXIT_IP" && -n "$IRAN_SELF_IP" ]] || {
  echo "usage: NEW_EXIT_IP=... IRAN_SELF_IP=... $0" >&2
  exit 2
}
[[ -f /etc/shahrah/backhaul.key ]] || { echo "missing /etc/shahrah/backhaul.key" >&2; exit 1; }

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../install.sh
source "$DIR/../install.sh"

export ROLE=relay WW_SIDE=iran WW_PEER="$NEW_EXIT_IP" WW_SELF="$IRAN_SELF_IP"
export WW_MODE="${WW_MODE:-reverse}" WW_TUNNEL_PORT="${WW_TUNNEL_PORT:-8443}"
export FIREWALL=0 CONF_DIR=/etc/shahrah

install_waterwall
systemctl restart shahrah-waterwall
echo "OK Iran WaterWall now peers with exit $NEW_EXIT_IP"
echo "On Germany: deploy/beta/germany-attach-waterwall.sh with IRAN_PEER_IP=$IRAN_SELF_IP"
