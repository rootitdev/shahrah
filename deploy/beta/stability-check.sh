#!/usr/bin/env bash
# Bounded beta stability (<=5 min, low traffic). Run on exit or from Iran with CLIENT_JSON.
# Does not reboot or load-test at scale.
set -euo pipefail

DURATION="${DURATION_SEC:-300}"
STATE="${STATE:-/etc/shahrah/state.json}"
XRAY_CFG="${XRAY_CFG:-/etc/shahrah/xray.json}"

[[ -f "$STATE" ]] || { echo "missing $STATE" >&2; exit 1; }
command -v shahrah >/dev/null || { echo "shahrah not in PATH" >&2; exit 1; }

end=$((SECONDS + DURATION))
echo "monitoring ${DURATION}s — RSS and xray active"
while ((SECONDS < end)); do
  date -u +%H:%M:%S
  systemctl is-active shahrah-xray 2>/dev/null || echo "shahrah-xray not active"
  free -m | awk '/Mem:/{print "mem_used_mb=" $3 " avail_mb=" $7}'
  pgrep -a xray | head -1 || true
  /usr/local/bin/xray run -test -c "$XRAY_CFG" >/dev/null 2>&1 && echo "xray-test ok" || echo "xray-test FAIL"
  sleep 30
done
echo "done (no production claim)"
