#!/usr/bin/env bash
# Payment provider → Shahrah settle-hook (HMAC). Domain/public CA still required for
# a real checkout callback URL; this is the signed POST shape once TLS is in front.
#
# Terminal A (panel host):
#   export SHAHRAH_SETTLE_SECRET=$(shahrah settle-hook --print-secret)
#   export SHAHRAH_PANEL_URL=https://127.0.0.1:8000
#   export SHAHRAH_PANEL_INSECURE_TLS=1
#   shahrah settle-hook --secret "$SHAHRAH_SETTLE_SECRET" --panel-url "$SHAHRAH_PANEL_URL"
#
# Terminal B (or your provider adapter):
#   shahrah settle-hook --secret "$SHAHRAH_SETTLE_SECRET" --emit-curl alice --days 30
#   # then run the printed curl
#
# Body aliases accepted by the hook: days, traffic_gb (see shahrah.settle.parse_event).
# Never commit real secrets or customer usernames into git.
set -euo pipefail
: "${SHAHRAH_SETTLE_SECRET:?set SHAHRAH_SETTLE_SECRET}"
USER="${1:?username}"
DAYS="${2:-30}"
exec shahrah settle-hook --secret "$SHAHRAH_SETTLE_SECRET" --emit-curl "$USER" --days "$DAYS"
