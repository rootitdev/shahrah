#!/usr/bin/env bash
# Iran side: register, render, and activate one named peer (multi-exit).
#
# Usage:
#   sudo PEER_NAME=de EXIT_IP=<EXIT1_IPV4> IRAN_IP=<IRAN_IPV4> ENTRY_HOST=<IRAN_IPV4> \
#     USER_PORT=443 TUNNEL_PORT=8443 ./deploy/beta/iran-bootstrap-relay-peer.sh
set -euo pipefail

PEER_NAME="${PEER_NAME:-}"
EXIT_IP="${EXIT_IP:-}"
IRAN_IP="${IRAN_IP:-}"
ENTRY_HOST="${ENTRY_HOST:-$IRAN_IP}"
USER_PORT="${USER_PORT:-443}"
TUNNEL_PORT="${TUNNEL_PORT:-8443}"

[[ -n "$PEER_NAME" && -n "$EXIT_IP" && -n "$IRAN_IP" ]] || {
  echo "set PEER_NAME, EXIT_IP, IRAN_IP" >&2
  exit 2
}

DIR="$(cd "$(dirname "$0")" && pwd)"
export SHAHRAH_WITH_KIT_FAILOVER=0 VPN_INFRA_KIT_ACTIVE=0

# Iran relay role may have installed WaterWall without Xray; ensure CLI + binary exist.
if [[ ! -x /usr/local/bin/shahrah ]]; then
  echo "install shahrah CLI first: deploy/install.sh --role relay --ww-peer $EXIT_IP" >&2
  exit 2
fi

command -v waterwall >/dev/null || {
  echo "install WaterWall first (install.sh --role relay or --with-waterwall iran)" >&2
  exit 2
}

shahrah relay peer-add --name "$PEER_NAME" --exit-ip "$EXIT_IP" \
  --user-port "$USER_PORT" --tunnel-port "$TUNNEL_PORT" \
  --iran-ip "$IRAN_IP" --entry-host "$ENTRY_HOST"

shahrah relay peer-activate --name "$PEER_NAME"
echo "Run the printed ufw + systemctl lines as root, then complete exit attach script."
