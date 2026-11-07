#!/usr/bin/env bash
# Permanent minimal Iran relay — WaterWall only (no Xray panel, no Docker, no kit).
#
# Users may still dial Germany directly; this adds domestic entry on Iran :443.
# Requires backhaul.key from Germany (from germany-attach-waterwall.sh).
#
# Usage (on Iran):
#   sudo EXIT_PEER_IP=<NL_IPV4> ./deploy/beta/iran-relay-install.sh
# Offline pip: SHAHRAH_WHEELHOUSE=/opt/wheelhouse (setuptools/wheel + shahrah sdist/wheel preseeded)
# After Germany copied backhaul.key to /etc/shahrah/backhaul.key on Iran.
set -euo pipefail

EXIT_PEER_IP="${EXIT_PEER_IP:-}"
[[ -n "$EXIT_PEER_IP" ]] || {
  echo "set EXIT_PEER_IP to the foreign exit public IPv4 (portable when exit is replaced)" >&2
  exit 2
}

DIR="$(cd "$(dirname "$0")" && pwd)"
export SHAHRAH_WITH_KIT_FAILOVER=0 VPN_INFRA_KIT_ACTIVE=0

if [[ ! -s /etc/shahrah/backhaul.key ]]; then
  echo "copy /etc/shahrah/backhaul.key from Germany first (germany-attach-waterwall.sh)" >&2
  exit 2
fi

WW_COVER="${WW_COVER_SNI:-www.speedtest.net}"
if [[ -n "${COVER_ADDR:-}" ]]; then
  WW_COVER="${WW_COVER}@${COVER_ADDR}"
fi

exec "$DIR/../install.sh" \
  --role relay \
  --ww-peer "$EXIT_PEER_IP" \
  --ww-mode "${WW_MODE:-reverse}" \
  --ww-tunnel-port "${WW_TUNNEL_PORT:-8443}" \
  --ww-cover "$WW_COVER" \
  --no-firewall
