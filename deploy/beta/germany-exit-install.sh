#!/usr/bin/env bash
# Staged BETA: Germany exit-only Shahrah node (1GB RAM safe path).
#
# Control plane: Shahrah only (brain enabled after panel bootstrap).
# No kit failover, no sales panels, no CDN/HY2/WARP extras by default.
#
# Prereqs on target: Ubuntu 22.04/24.04/26.04, Python >=3.11, ports 22+443 free.
#
# Usage on Germany VPS (from unpacked beta release):
#   sudo REALITY_HOST=reality.bluelark.ir ./deploy/beta/germany-exit-install.sh
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
HOST="${REALITY_HOST:-}"
TARGET="${REALITY_TARGET:-www.cloudflare.com}"

[[ -n "$HOST" ]] || {
  echo "set REALITY_HOST to the DNS-only REALITY hostname (e.g. reality.bluelark.ir)" >&2
  exit 2
}

export SHAHRAH_WITH_KIT_FAILOVER=0
export VPN_INFRA_KIT_ACTIVE=0

cd "$ROOT"
exec "$ROOT/deploy/install.sh" \
  --host "$HOST" \
  --target "$TARGET" \
  --port 443 \
  --profile reality-vision \
  --no-firewall
