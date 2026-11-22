#!/usr/bin/env bash
# NON-DESTRUCTIVE restore drill: decrypt bundle into an isolated dir and validate metadata.
# Never writes to /etc/shahrah or restarts services.
set -euo pipefail

ARCHIVE="${1:?pass path to .tar.gz.gpg}"
PASS_FILE="${BACKUP_PASS_FILE:-/etc/shahrah/backup.pass}"
LIVE="${LIVE_STATE:-/etc/shahrah/state.json}"
ROOT="${DRILL_ROOT:-/var/lib/shahrah-restore-drill-$$}"

[[ -f "$ARCHIVE" ]] || exit 1
[[ -s "$PASS_FILE" ]] || { echo "missing passphrase file (same host as backup)" >&2; exit 1; }

mkdir -p "$ROOT"
gpg --batch --yes --passphrase-file "$PASS_FILE" -d "$ARCHIVE" | tar -xzf - -C "$ROOT"

test -f "$ROOT/state.json" || { echo "drill: no state.json in bundle" >&2; exit 1; }
python3 - <<'PY' "$ROOT/state.json" "$LIVE"
import json, sys
drill, live = sys.argv[1:3]
d = json.load(open(drill))
print("drill_users", len(d.get("users", [])))
print("drill_public_host", d.get("public_host", ""))
try:
    l = json.load(open(live))
    if d.get("public_key") != l.get("public_key"):
        print("NOTE: drill public_key differs from live (expected if drill is old)")
    if d.get("users") != l.get("users"):
        print("NOTE: user list differs — drill does NOT overwrite live")
except FileNotFoundError:
    print("live state absent — drill-only host")
PY

test -f "$ROOT/xray.json" && /usr/local/bin/xray run -test -c "$ROOT/xray.json" 2>/dev/null \
  && echo "xray-test on drill config: OK" || echo "xray-test skipped or failed"
echo "drill root $ROOT (remove manually: rm -rf $ROOT)"
