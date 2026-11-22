#!/usr/bin/env bash
# Production bridge until PasarGuard node owns the exit Xray (hybrid mode).
# Copies panel user UUIDs into /etc/shahrah/state.json and reapplies shahrah-xray.
set -euo pipefail
ENVF=/root/.vpn-secrets/.env
[[ -f "$ENVF" ]] || exit 0
set -a
# shellcheck disable=SC1090
source "$ENVF"
set +a
URL="${SHAHRAH_PANEL_URL:-https://panel.example.com}"
KEY="${SHAHRAH_PANEL_API_KEY:-}"
[[ -n "$KEY" ]] || exit 0
STATE=/etc/shahrah/state.json
ADDED=$(python3 - "$URL" "$KEY" "$STATE" <<'PY'
import json, sys, urllib.request

url, key, state_path = sys.argv[1:4]
req = urllib.request.Request(
    url.rstrip("/") + "/api/users?limit=500",
    headers={"X-Api-Key": key},
)
data = json.loads(urllib.request.urlopen(req, timeout=30).read())
users = data.get("users") or data
state = json.load(open(state_path))
have = {u["uuid"] for u in state.get("users", [])}
added = 0
for u in users:
    vless = (u.get("proxy_settings") or {}).get("vless") or {}
    uid = vless.get("id")
    label = u.get("username") or uid
    if not uid or uid in have:
        continue
    state.setdefault("users", []).append({"label": str(label)[:32], "uuid": uid})
    have.add(uid)
    added += 1
if added:
    json.dump(state, open(state_path, "w"), indent=2)
print(added)
PY
)
echo "sync added=$ADDED"
if [[ "$ADDED" != "0" ]]; then
  /opt/shahrah/venv/bin/shahrah --state "$STATE" apply \
    --xray-bin /usr/local/bin/xray \
    --config-out /etc/shahrah/xray.json \
    --group shahrah
  python3 - <<'PY'
import json

c = json.load(open("/etc/shahrah/xray.json"))
c["log"] = {"loglevel": "warning", "access": "/var/lib/shahrah/access.log"}
json.dump(c, open("/etc/shahrah/xray.json", "w"), indent=2)
PY
  systemctl restart shahrah-xray
fi