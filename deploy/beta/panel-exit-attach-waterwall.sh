#!/usr/bin/env bash
# WaterWall exit leg when PasarGuard panel **node** owns TCP :443 Xray (no Shahrah state.json).
#
# Prereqs: PasarGuard node running locally on 127.0.0.1:443; Iran relay IP known.
# Does NOT install/start shahrah-xray or write state.json users.
#
# Usage (on foreign exit / NL):
#   sudo IRAN_PEER_IP=<IRAN_IPV4> ./deploy/beta/panel-exit-attach-waterwall.sh
# Optional: PANEL_EXIT_SERVICE=127.0.0.1:443 WW_TUNNEL_PORT=8443 WW_MODE=reverse
set -euo pipefail

IRAN_PEER_IP="${IRAN_PEER_IP:-}"
[[ -n "$IRAN_PEER_IP" ]] || {
  echo "set IRAN_PEER_IP to the Iran relay public IPv4" >&2
  exit 2
}

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../install.sh
source "$DIR/../install.sh"

[[ "$(id -u)" -eq 0 ]] || die "run as root"

export PANEL_OWNED=1
export ROLE=node WW_SIDE=exit WW_PEER="$IRAN_PEER_IP"
export WW_EXIT_SERVICE="${PANEL_EXIT_SERVICE:-127.0.0.1:443}"
export WW_MODE="${WW_MODE:-reverse}"
export WW_TUNNEL_PORT="${WW_TUNNEL_PORT:-8443}"
export WW_COVER_SNI="${WW_COVER_SNI:-www.speedtest.net}"
export FIREWALL=0 WITH_PAQET=0 WITH_WARP=0 WITH_HY2=0
if [[ -n "${COVER_ADDR:-}" ]]; then
  export WW_COVER_ADDR="$COVER_ADDR"
fi

enforce_control_plane
ensure_shahrah_cli || die "bootstrap CLI from /opt/shahrah source first"
setup_user_and_dirs
install_waterwall
write_install_manifest

echo "OK panel-owned WaterWall exit (peer=${IRAN_PEER_IP} tunnel=${WW_TUNNEL_PORT} service=${WW_EXIT_SERVICE})"
echo "Next: scp /etc/shahrah/backhaul.key root@${IRAN_PEER_IP}:/etc/shahrah/backhaul.key"
echo "Then on Iran: SHAHRAH_WHEELHOUSE=/path/to/wheels sudo EXIT_PEER_IP=<NL_IPV4> ./deploy/beta/iran-relay-install.sh"
