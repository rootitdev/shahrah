#!/usr/bin/env bash
# Add VLESS xhttp entry on TCP/53 via a second WaterWall chain (tunnel 8553 -> exit :53).
# Run on Iran first, then on Netherlands exit. Same backhaul key as main :443 chain.
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "run as root" >&2; exit 1; }
IRAN_IP="${IRAN_IP:-}"
EXIT_IP="${EXIT_IP:-}"
KEY_FILE="${KEY_FILE:-/etc/shahrah/backhaul.key}"
TUNNEL_53="${TUNNEL_53:-8553}"
WW="${WW:-/opt/shahrah/venv/bin/shahrah}"
ROLE="${1:-}"
[[ -n "$IRAN_IP" && -n "$EXIT_IP" ]] || {
  echo "usage: IRAN_IP=... EXIT_IP=... $0 iran|exit" >&2
  exit 2
}
WW_DIR=/etc/shahrah/waterwall
case "$ROLE" in
  iran)
    "$WW" waterwall-config iran --iran-ip "$IRAN_IP" --exit-ip "$EXIT_IP" --key-file "$KEY_FILE" \
      --mode reverse --user-port 53 --tunnel-port "$TUNNEL_53"
    mv -f "$WW_DIR/config.json" "$WW_DIR/config-53.json"
    "$WW" waterwall-config iran --iran-ip "$IRAN_IP" --exit-ip "$EXIT_IP" --key-file "$KEY_FILE" \
      --mode reverse --user-port 443 --tunnel-port 8443 --out-dir "$WW_DIR"
  ;;
  exit)
    "$WW" waterwall-config exit --iran-ip "$IRAN_IP" --exit-ip "$EXIT_IP" --key-file "$KEY_FILE" \
      --mode reverse --user-port 53 --tunnel-port "$TUNNEL_53" --exit-service 127.0.0.1:53
    mv -f "$WW_DIR/config.json" "$WW_DIR/config-53.json"
    "$WW" waterwall-config exit --iran-ip "$IRAN_IP" --exit-ip "$EXIT_IP" --key-file "$KEY_FILE" \
      --mode reverse --user-port 443 --tunnel-port 8443 --exit-service 127.0.0.1:443 --out-dir "$WW_DIR"
  ;;
  *) echo "role must be iran or exit" >&2; exit 2 ;;
esac
python3 - <<'PY'
import json
from pathlib import Path
p = Path("/etc/shahrah/waterwall/core.json")
core = json.loads(p.read_text(encoding="utf-8"))
core["configs"] = ["config.json", "config-53.json"]
p.write_text(json.dumps(core, indent=2) + "\n")
print("core.json configs:", core["configs"])
PY
systemctl restart shahrah-waterwall