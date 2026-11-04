#!/usr/bin/env bash
# Control vantage: probe exits from a *free* network and publish a burn-control report.
# The Iran field brain reads this via --control-report (https://… or a local path).
#
# Example cron on a free VPS (not the filtered vantage):
#   */2 * * * * /etc/shahrah/publish-control.sh
#
# Replace paths; never commit real URLs or IPs into git.
set -euo pipefail

CONFIG="${SHAHRAH_BRAIN_CONFIG:-/var/lib/shahrah/brain.json}"
OUT="${SHAHRAH_CONTROL_OUT:-/var/lib/shahrah/control-report.json}"
XRAY="${SHAHRAH_XRAY_BIN:-/usr/local/bin/xray}"

umask 077
/usr/local/bin/shahrah brain \
  --config "$CONFIG" \
  --xray-bin "$XRAY" \
  --once \
  --write-report "$OUT"

# Optional: copy to a static HTTPS root the field vantage can fetch.
#   install -m 0644 "$OUT" /var/www/html/shahrah-control.json
logger -t shahrah-control "wrote $OUT"
