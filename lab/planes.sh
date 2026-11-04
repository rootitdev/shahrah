#!/usr/bin/env bash
# Start every data plane in the lab namespaces from Shahrah-rendered configs and the
# *pinned* binaries (sha256 checked against deploy/install.sh). Usage: planes.sh up|down
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
RUN=/run/shahrah-lab
BIN="${SHAHRAH_LAB_BIN:-/root/shahrah-lab-bin}"
export PYTHONPATH="$REPO/src"
SH="python3 -m shahrah --state $RUN/exit-state.json"

pin() { grep -E "^$1=" "$REPO/deploy/install.sh" | head -n1 | cut -d'"' -f2; }

fetch() { # url file sha
  [[ -s "$BIN/$2" ]] || curl -fsSL --retry 3 -o "$BIN/$2" "$1"
  local got; got="$(sha256sum "$BIN/$2" | awk '{print $1}')"
  [[ "$got" == "$3" ]] || { echo "checksum mismatch for $2: $got" >&2; rm -f "$BIN/$2"; exit 1; }
}

binaries() {
  mkdir -p "$BIN"
  fetch "https://github.com/XTLS/Xray-core/releases/download/$(pin PINNED_VERSION)/Xray-linux-64.zip" \
    xray.zip "$(pin PINNED_SHA256_AMD64)"
  fetch "https://github.com/apernet/hysteria/releases/download/$(pin HY2_VERSION)/hysteria-linux-amd64" \
    hysteria "$(pin HY2_SHA256_AMD64)"
  fetch "https://github.com/radkesvat/WaterWall/releases/download/$(pin WW_VERSION)/Waterwall-linux-gcc-x64.zip" \
    ww.zip "$(pin WW_SHA256_X64)"
  local pv; pv="$(pin PAQET_VERSION)"
  fetch "https://github.com/hanselime/paqet/releases/download/$pv/paqet-linux-amd64-$pv.tar.gz" \
    paqet.tgz "$(pin PAQET_SHA256_AMD64)"
  (cd "$BIN" && python3 -c 'import zipfile; zipfile.ZipFile("xray.zip").extract("xray"); zipfile.ZipFile("ww.zip").extract("Waterwall")' \
    && tar -xzf paqet.tgz paqet_linux_amd64 && chmod +x xray hysteria Waterwall paqet_linux_amd64)
}

certs() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -subj "/CN=Shahrah Lab CA" -keyout "$RUN/ca.key" -out "$RUN/ca.crt" 2>/dev/null
  leaf cover cover.lab; leaf hy2 exit.lab
}
leaf() {
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$2" \
    -keyout "$RUN/$1.key" -out "$RUN/$1.csr" 2>/dev/null
  openssl x509 -req -in "$RUN/$1.csr" -CA "$RUN/ca.crt" -CAkey "$RUN/ca.key" -CAcreateserial \
    -days 2 -extfile <(printf 'subjectAltName=DNS:%s' "$2") -out "$RUN/$1.crt" 2>/dev/null
}

bg() { # ns name cmd...  (logs in $RUN/<name>.log, pid in $RUN/<name>.pid)
  local ns="$1" name="$2"; shift 2
  ip netns exec "$ns" "$@" >"$RUN/$name.log" 2>&1 &
  echo $! > "$RUN/$name.pid"
}

up() {
  rm -rf "$RUN"; mkdir -p "$RUN/ww-iran" "$RUN/ww-exit"; echo truth > "$RUN/dns_mode"
  binaries; certs
  bg cover cover python3 "$HERE/cover.py" "$RUN/cover.crt" "$RUN/cover.key"
  bg censor dnsd python3 "$HERE/dnsd.py" 10.0.1.1

  # exit node: REALITY Vision 443 + REALITY XHTTP 80, Hysteria2 udp/8443 (salamander, pinned)
  $SH init --host 10.0.4.2 --target cover.lab --extra-listener 80:reality-xhttp >/dev/null
  $SH user add probe >/dev/null
  $SH hysteria2 enable --port 8443 --sni exit.lab --cert "$RUN/hy2.crt" \
    --cert-path "$RUN/hy2.crt" --key-path "$RUN/hy2.key" >/dev/null
  $SH apply --xray-bin "$BIN/xray" --config-out "$RUN/xray-exit.json" >/dev/null
  $SH hysteria2 server --out "$RUN/hy2-server.yaml" >/dev/null
  bg exit xray-exit "$BIN/xray" run -c "$RUN/xray-exit.json"
  bg exit hy2-exit "$BIN/hysteria" server -c "$RUN/hy2-server.yaml" --disable-update-check

  # WaterWall relay: users dial iran:443, exit dials iran:8443 (reverse), cover pinned by IP
  local ww=(--iran-ip 10.0.2.2 --exit-ip 10.0.4.2 --key-file "$RUN/backhaul.key"
    --cover-sni cover.lab --cover-addr 23.5.100.2 --exit-service 127.0.0.1:443 --no-verify-cover)
  python3 -m shahrah waterwall-config iran "${ww[@]}" --out-dir "$RUN/ww-iran" >/dev/null
  python3 -m shahrah waterwall-config exit "${ww[@]}" --out-dir "$RUN/ww-exit" >/dev/null
  for side in iran exit; do
    sed -i "s#/var/log/shahrah-ww/#$RUN/ww-$side/log/#" "$RUN/ww-$side/core.json"
    (cd "$RUN/ww-$side" && bg "$side" "ww-$side" "$BIN/Waterwall" -c:core.json)
  done

  # paqet: server on the exit, client in the client namespace (raw frames through the censor)
  local cmac emac
  cmac="$("$HERE/topo.sh" mac censor c1)"; emac="$("$HERE/topo.sh" mac inet e1)"
  python3 -m shahrah paqet-config server --interface e0 --ip 10.0.4.2 --router-mac "$emac" \
    --port 9999 --key-file "$RUN/paqet.key" --out "$RUN/paqet-server.yaml"
  python3 -m shahrah paqet-config client --interface c0 --ip 10.0.1.2 --router-mac "$cmac" \
    --server-ip 10.0.4.2 --port 9999 --key-file "$RUN/paqet.key" --out "$RUN/paqet-client.yaml"
  python3 -m shahrah paqet-config firewall --port 9999 | while read -r l; do ip netns exec exit $l; done
  bg exit paqet-exit "$BIN/paqet_linux_amd64" run -c "$RUN/paqet-server.yaml"
  sleep 1
  bg client paqet-client "$BIN/paqet_linux_amd64" run -c "$RUN/paqet-client.yaml"
  sleep 3
  for f in "$RUN"/*.pid; do
    kill -0 "$(cat "$f")" 2>/dev/null || { echo "$(basename "$f" .pid) died:" >&2; tail -n 5 "${f%.pid}.log" >&2; exit 1; }
  done
  echo "data planes up"
}

down() {
  for f in "$RUN"/*.pid; do [[ -f "$f" ]] && kill "$(cat "$f")" 2>/dev/null || true; done
  echo "data planes down"
}

case "${1:-}" in up) up ;; down) down ;; *) echo "usage: $0 up|down" >&2; exit 2 ;; esac
