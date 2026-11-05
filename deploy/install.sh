#!/usr/bin/env bash
# shahrah node installer.
#
# Supported: Debian 12+ / Ubuntu 22.04+ (needs Python >= 3.11), x86_64 or aarch64, run as root.
# Idempotent: re-running upgrades the software and keeps the existing keys and users.
#
#   sudo ./deploy/install.sh --host vpn.example.org --target www.cloudflare.com
#
# Secrets (REALITY private key, user ids) are generated on the machine and never leave it.
set -Eeuo pipefail

XRAY_VERSION="${XRAY_VERSION:-v26.10.21}"
# SHA-256 of the pinned release archives (cross-checked against the upstream .dgst files).
PINNED_VERSION="v26.10.21"
PINNED_SHA256_AMD64="0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978"
PINNED_SHA256_ARM64="d1304946c486d98e6b886e9b931eaaaebb23835b30e217638037b7f2721d4e9c"

# paqet raw-packet crisis path (MIT, https://github.com/hanselime/paqet); opt-in, see
# docs/ALLOWLIST.md. Digests from the GitHub release assets.
PAQET_VERSION="v1.0.0-alpha.21"
PAQET_SHA256_AMD64="4f2f69e0493746726598485ef18df43372470a1514f8021594137e522f0f4fc7"
PAQET_SHA256_ARM64="be5c7b35a0a93832063e1dc7fddeb76d4597fb9de76abdfdf7b8574b775e3885"

# Hysteria2 QUIC/UDP social path (MIT, https://github.com/apernet/hysteria); opt-in.
HY2_VERSION="app/v2.13.0"
HY2_SHA256_AMD64="907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691"
HY2_SHA256_ARM64="a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7"

# WaterWall Iran<->exit backhaul (MPL-2.0, https://github.com/radkesvat/WaterWall); opt-in.
WW_VERSION="v1.5.2"
WW_SHA256_X64="1d9ba7da4a3ab42b5685e5ecf03cf3d93a97ede5fd9fce8a12dbfc23e04a829a"
WW_SHA256_ARM64="56486a3a8d02a67f782d45a6155bea4e437348c72611a3f685459d97966ff96b"

# wgcf (MIT, https://github.com/ViRb3/wgcf) — WARP account + WireGuard profile for --with-warp.
WGCF_VERSION="2.2.29"
WGCF_SHA256_AMD64="572d102720ee39a6a0a6a22a0b4689fdf92b8974ede927111e3daf8d2ed5dec1"
WGCF_SHA256_ARM64="6228ae03ce2004edb24888aa119d7bd3978004964113f9f1e00841db1b01313c"

APP_DIR="/opt/shahrah"
CONF_DIR="/etc/shahrah"
SERVICE_USER="shahrah"
SERVICE_NAME="shahrah-xray"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ROLE="node"
HOST=""
TARGET="www.cloudflare.com"
PROFILE="reality-vision"
PORT="443"
SSH_PORT=""
EXTRA_LISTENERS=()
FIREWALL=1
WITH_PAQET=0
PAQET_PORT="9999"
WITH_HY2=0
HY2_PORT="8443"
WITH_WARP=0
WARP_ROUTE_ALL=0
HY2_HOP=""
WW_SIDE=""
WW_PEER=""
WW_SELF=""
WW_MODE="reverse"
WW_TUNNEL_PORT="8443"
WW_COVER_SNI="www.speedtest.net"
WW_COVER_ADDR=""
WORK_DIR=""
trap '[[ -z "$WORK_DIR" ]] || rm -rf "$WORK_DIR"' EXIT

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: install.sh --host HOST [options]      (VPN exit/entry node)
       install.sh --role brain               (health prober + panel steering)

  --role ROLE       node (default), brain, or relay (Iran relay: WaterWall only, no Xray)
  --host HOST       public domain or IP address clients connect to (node only, required)
  --target DOMAIN   TLS 1.3 site REALITY imitates (default: www.cloudflare.com)
  --profile NAME    reality-vision (default) or reality-xhttp
  --port PORT       listen port (default 443; other ports weaken allowlist survival)
  --extra-listener PORT:PROFILE
                    additional listening port, repeatable (e.g. 80:reality-xhttp, or a CDN origin\n                    8080:cdn-xhttp:cdn.example.com[:PATH[:http]])
  --multi-port      preset: also listen on 53 with reality-xhttp (443 + 53; port 80 REALITY dropped)
  --ssh-port PORT   SSH port kept open in the firewall (default: auto-detect, else 22)
  --no-firewall     do not touch ufw
  --with-paqet PORT also run a paqet server (raw-packet crisis path) on PORT (not 80/443)
  --with-hysteria2 PORT
                    also run a Hysteria2 server (salamander, social tuning) on UDP PORT
  --hy2-hop LOW-HIGH
                    UDP port-hopping range DNAT-ed to the Hysteria2 port
  --with-waterwall iran|exit
                    WaterWall backhaul side (relay role implies iran)
  --ww-peer IP      the other server's public IP (required with --with-waterwall)
  --ww-self IP      this server's public IP (default: auto-detect)
  --ww-mode MODE    reverse (default: exit dials Iran) or direct
  --ww-tunnel-port PORT
                    inter-server leg port (default 8443)
  --ww-cover SNI[@IP]
                    cover site for the backhaul Reality leg; @IP pins it (no DNS per handshake)
  -h, --help        show this help
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --role) ROLE="${2:?--role needs a value}"; shift 2 ;;
      --host) HOST="${2:?--host needs a value}"; shift 2 ;;
      --target) TARGET="${2:?--target needs a value}"; shift 2 ;;
      --profile) PROFILE="${2:?--profile needs a value}"; shift 2 ;;
      --port) PORT="${2:?--port needs a value}"; shift 2 ;;
      --extra-listener) EXTRA_LISTENERS+=("${2:?--extra-listener needs PORT:PROFILE}"); shift 2 ;;
      # Port-80 REALITY+XHTTP fails on current Xray (loopback timeout); keep 53 only.
      --multi-port) EXTRA_LISTENERS+=("53:reality-xhttp"); shift ;;
      --ssh-port) SSH_PORT="${2:?--ssh-port needs a value}"; shift 2 ;;
      --no-firewall) FIREWALL=0; shift ;;
      --with-paqet) WITH_PAQET=1; PAQET_PORT="${2:?--with-paqet needs a PORT}"; shift 2 ;;
      --with-hysteria2) WITH_HY2=1; HY2_PORT="${2:?--with-hysteria2 needs a PORT}"; shift 2 ;;
      --hy2-hop) HY2_HOP="${2:?--hy2-hop needs LOW-HIGH}"; shift 2 ;;
      --with-warp) WITH_WARP=1; shift ;;
      --warp-route-all) WARP_ROUTE_ALL=1; shift ;;
      --with-waterwall) WW_SIDE="${2:?--with-waterwall needs iran or exit}"; shift 2 ;;
      --ww-peer) WW_PEER="${2:?--ww-peer needs an IP}"; shift 2 ;;
      --ww-self) WW_SELF="${2:?--ww-self needs an IP}"; shift 2 ;;
      --ww-mode) WW_MODE="${2:?--ww-mode needs reverse or direct}"; shift 2 ;;
      --ww-tunnel-port) WW_TUNNEL_PORT="${2:?--ww-tunnel-port needs a PORT}"; shift 2 ;;
      --ww-cover) WW_COVER_SNI="${2%%@*}"; [[ "$2" == *@* ]] && WW_COVER_ADDR="${2#*@}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; die "unknown option: $1" ;;
    esac
  done
  case "$ROLE" in
    node) [[ -n "$HOST" ]] || { usage >&2; die "--host is required for a node"; } ;;
    brain) ;;
    relay) WW_SIDE="iran" ;;
    *) die "--role must be node, brain or relay" ;;
  esac
  case "$WW_SIDE" in
    "") ;;
    iran|exit) [[ -n "$WW_PEER" ]] || die "--with-waterwall needs --ww-peer IP" ;;
    *) die "--with-waterwall must be iran or exit" ;;
  esac
}

check_system() {
  [[ "$(id -u)" -eq 0 ]] || die "run as root (sudo)"
  command -v apt-get >/dev/null || die "only Debian/Ubuntu (apt) is supported"
  command -v systemctl >/dev/null || die "systemd is required"
}

PYTHON_BIN="python3"

install_packages() {
  log "installing system packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  local pkgs=(python3 python3-venv unzip curl ca-certificates ufw)
  if [[ "$WITH_WARP" -eq 1 ]]; then
    pkgs+=(wireguard-tools)
  fi
  apt-get install -y -qq "${pkgs[@]}" >/dev/null
  if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
    # Ubuntu 22.04 ships 3.10 as the default; 3.11 is available as a parallel package.
    log "default $(python3 -V) is too old; installing python3.11"
    apt-get install -y -qq python3.11 python3.11-venv >/dev/null \
      || die "Python >= 3.11 is required and python3.11 could not be installed"
    PYTHON_BIN="python3.11"
  fi
  "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
    || die "Python >= 3.11 is required (found $($PYTHON_BIN -V))"
}

free_public_ports() {
  # A re-used VPS often still has nginx / an old Xray / a reverse proxy on 443/80/53.
  local port listener
  for port in "$PORT" "${EXTRA_LISTENERS[@]%%:*}"; do
    [[ -n "$port" ]] || continue
    while read -r listener; do
      [[ -n "$listener" ]] || continue
      case "$listener" in
        *'"xray"'*|*"shahrah-xray"*) continue ;;
      esac
      log "port ${port} is busy ($listener); stopping common leftovers (nginx, xray, caddy)"
      systemctl stop nginx xray caddy path-web 2>/dev/null || true
      systemctl disable nginx xray caddy path-web 2>/dev/null || true
      break
    done < <(ss -ltnpH "sport = :${port}" 2>/dev/null || true)
    if ss -ltnpH "sport = :${port}" 2>/dev/null | grep -vE '"xray"|shahrah-xray' | grep -q .; then
      die "TCP port ${port} is still in use; stop the process and re-run the installer"
    fi
  done
}

install_xray() {
  local asset expected actual
  case "$(uname -m)" in
    x86_64|amd64) asset="Xray-linux-64.zip"; expected="$PINNED_SHA256_AMD64" ;;
    aarch64|arm64) asset="Xray-linux-arm64-v8a.zip"; expected="$PINNED_SHA256_ARM64" ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
  local base="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}"
  WORK_DIR="$(mktemp -d)"

  log "downloading Xray ${XRAY_VERSION}"
  curl -fsSL --retry 3 -o "$WORK_DIR/$asset" "$base/$asset"
  if [[ "$XRAY_VERSION" != "$PINNED_VERSION" ]]; then
    printf 'warning: %s is not the pinned version; trusting the upstream .dgst checksum\n' \
      "$XRAY_VERSION" >&2
    curl -fsSL --retry 3 -o "$WORK_DIR/$asset.dgst" "$base/$asset.dgst"
    expected="$(awk -F'= *' '/^SHA2-256=/{print $2}' "$WORK_DIR/$asset.dgst" | tr -d '[:space:]')"
    [[ -n "$expected" ]] || die "could not read the SHA2-256 checksum for $asset"
  fi
  actual="$(sha256sum "$WORK_DIR/$asset" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || die "checksum mismatch for $asset (expected $expected, got $actual)"

  unzip -q -o "$WORK_DIR/$asset" xray -d "$WORK_DIR"
  install -m 0755 "$WORK_DIR/xray" /usr/local/bin/xray
  log "installed $(/usr/local/bin/xray version | head -n 1)"
}

# --- gateway discovery (paqet crafts Ethernet frames, so it needs the next hop's MAC) ------
# Each step falls back to the next: VPS images differ (no iproute2 neigh entry yet, onlink
# /32 gateways, arping missing, containers without ping). Overridable for tests.
ROUTE_TABLE="${ROUTE_TABLE:-/proc/net/route}"
ARP_TABLE="${ARP_TABLE:-/proc/net/arp}"
MAC_RE='^([0-9a-f]{2}:){5}[0-9a-f]{2}$'

default_iface() {
  local iface
  iface="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
  if [[ -z "$iface" && -r "$ROUTE_TABLE" ]]; then
    iface="$(awk 'NR>1 && $2=="00000000" {print $1; exit}' "$ROUTE_TABLE")"
  fi
  printf '%s\n' "$iface"
}

default_gateway() {
  local iface="$1" gw hex
  gw="$(ip -4 route show default ${iface:+dev "$iface"} 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')"
  if [[ -z "$gw" && -r "$ROUTE_TABLE" ]]; then
    # /proc/net/route stores the gateway as little-endian hex
    hex="$(awk -v d="$iface" 'NR>1 && $2=="00000000" && (d=="" || $1==d) {print $3; exit}' "$ROUTE_TABLE")"
    if [[ -n "$hex" && "$hex" != "00000000" ]]; then
      gw="$(printf '%d.%d.%d.%d' "0x${hex:6:2}" "0x${hex:4:2}" "0x${hex:2:2}" "0x${hex:0:2}")"
    fi
  fi
  printf '%s\n' "$gw"
}

gateway_mac() {
  local gw="$1" iface="$2" mac=""
  if [[ -n "${PAQET_ROUTER_MAC:-}" ]]; then
    mac="${PAQET_ROUTER_MAC,,}"
  elif [[ -n "$gw" ]]; then
    ping -c1 -W1 "$gw" >/dev/null 2>&1 || true  # populate the neighbour table
    mac="$(ip neigh show "$gw" ${iface:+dev "$iface"} 2>/dev/null \
      | awk '!/FAILED|INCOMPLETE/ {for(i=1;i<=NF;i++) if($i=="lladdr"){print $(i+1); exit}}')"
    if [[ -z "$mac" ]] && command -v arping >/dev/null 2>&1; then
      mac="$(arping -c 2 -w 3 ${iface:+-I "$iface"} "$gw" 2>/dev/null \
        | grep -oiE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -n 1 || true)"
    fi
    if [[ -z "$mac" && -r "$ARP_TABLE" ]]; then
      mac="$(awk -v gw="$gw" 'NR>1 && $1==gw && $3!="0x0" && $4!="00:00:00:00:00:00" {print $4; exit}' "$ARP_TABLE")"
    fi
  fi
  if [[ -z "$mac" && -r "$ARP_TABLE" ]]; then
    # onlink/point-to-point setups: the only complete neighbour on the uplink is the router
    mac="$(awk -v d="$iface" 'NR>1 && $3!="0x0" && (d=="" || $6==d) {print $4; exit}' "$ARP_TABLE")"
  fi
  mac="${mac,,}"
  [[ "$mac" =~ $MAC_RE ]] || return 1
  printf '%s\n' "$mac"
}

arch_suffix() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
}

install_hysteria2() {
  local arch expected actual dir sni hop_args=() port_rule
  arch="$(arch_suffix)"
  [[ "$arch" == amd64 ]] && expected="$HY2_SHA256_AMD64" || expected="$HY2_SHA256_ARM64"
  dir="$(mktemp -d)"
  log "downloading hysteria ${HY2_VERSION}"
  curl -fsSL --retry 3 -o "$dir/hysteria" \
    "https://github.com/apernet/hysteria/releases/download/${HY2_VERSION}/hysteria-linux-${arch}"
  actual="$(sha256sum "$dir/hysteria" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || die "checksum mismatch for hysteria (expected $expected, got $actual)"
  install -m 0755 "$dir/hysteria" /usr/local/bin/hysteria
  rm -rf "$dir"

  # Self-signed certificate, pinned by clients (leaf DER sha256). Name: the node's domain, or
  # the REALITY target when the node is addressed by IP.
  if [[ "$HOST" =~ ^[0-9.]+$ || "$HOST" == *:* ]]; then sni="$TARGET"; else sni="$HOST"; fi
  if [[ ! -s "$CONF_DIR/hy2.crt" ]]; then
    command -v openssl >/dev/null || apt-get install -y -qq openssl >/dev/null
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -subj "/CN=${sni}" -addext "subjectAltName=DNS:${sni}" \
      -keyout "$CONF_DIR/hy2.key" -out "$CONF_DIR/hy2.crt" 2>/dev/null
  fi
  chown root:"$SERVICE_USER" "$CONF_DIR/hy2.crt" "$CONF_DIR/hy2.key"
  chmod 0640 "$CONF_DIR/hy2.crt" "$CONF_DIR/hy2.key"
  [[ -z "$HY2_HOP" ]] || hop_args=(--hop "$HY2_HOP")
  shahrah --state "$CONF_DIR/state.json" hysteria2 enable --port "$HY2_PORT" --sni "$sni" \
    --cert "$CONF_DIR/hy2.crt" "${hop_args[@]}" >/dev/null
  shahrah --state "$CONF_DIR/state.json" hysteria2 server --out "$CONF_DIR/hysteria2.yaml" >/dev/null
  chown root:"$SERVICE_USER" "$CONF_DIR/hysteria2.yaml"
  chmod 0640 "$CONF_DIR/hysteria2.yaml"
  shahrah hysteria2 unit --unit-role server --config-path "$CONF_DIR/hysteria2.yaml" \
    > /etc/systemd/system/shahrah-hysteria2.service
  local line
  while IFS= read -r line; do
    # shellcheck disable=SC2086
    ${line/ -A / -C } >/dev/null 2>&1 || $line
  done < <(shahrah --state "$CONF_DIR/state.json" hysteria2 hop-rules --interface "$(default_iface)")
  if [[ "$FIREWALL" -eq 1 ]] && command -v ufw >/dev/null; then
    ufw allow "${HY2_PORT}/udp" >/dev/null
    if [[ -n "$HY2_HOP" ]]; then port_rule="${HY2_HOP/-/:}/udp"; ufw allow "$port_rule" >/dev/null; fi
  fi
  systemctl daemon-reload
  systemctl enable --now shahrah-hysteria2 >/dev/null
  systemctl restart shahrah-hysteria2
  log "hysteria2 on udp/${HY2_PORT}${HY2_HOP:+ (hop ${HY2_HOP})}; links now include hysteria2://"
  log "  after user changes: shahrah hysteria2 server --out $CONF_DIR/hysteria2.yaml && systemctl restart shahrah-hysteria2"
}


install_warp() {
  local arch expected actual dir route_args=()
  arch="$(arch_suffix)"
  [[ "$arch" == amd64 ]] && expected="$WGCF_SHA256_AMD64" || expected="$WGCF_SHA256_ARM64"
  dir="$(mktemp -d)"
  log "downloading wgcf v${WGCF_VERSION}"
  curl -fsSL --retry 3 -o "$dir/wgcf" \
    "https://github.com/ViRb3/wgcf/releases/download/v${WGCF_VERSION}/wgcf_${WGCF_VERSION}_linux_${arch}"
  actual="$(sha256sum "$dir/wgcf" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || die "checksum mismatch for wgcf (expected $expected, got $actual)"
  install -m 0755 "$dir/wgcf" /usr/local/bin/wgcf
  rm -rf "$dir"

  # Register a free WARP account once; keep the profile on the box (never in git).
  if [[ ! -s "$CONF_DIR/wgcf-account.toml" ]]; then
    log "registering Cloudflare WARP account via wgcf"
    (cd "$CONF_DIR" && wgcf register --accept-tos >/dev/null)
  fi
  if [[ ! -s "$CONF_DIR/wgcf-profile.conf" ]]; then
    (cd "$CONF_DIR" && wgcf generate -p "$CONF_DIR/wgcf-profile.conf" >/dev/null) \
      || (cd "$CONF_DIR" && wgcf generate >/dev/null)
  fi
  chmod 0600 "$CONF_DIR/wgcf-account.toml" "$CONF_DIR/wgcf-profile.conf"
  [[ "$WARP_ROUTE_ALL" -eq 0 ]] || route_args=(--route-all)
  # Default: Google-family only via Xray's native WireGuard outbound (no system routes/DNS).
  shahrah --state "$CONF_DIR/state.json" warp enable --profile "$CONF_DIR/wgcf-profile.conf" \
    --interface warp "${route_args[@]}" >/dev/null
  shahrah --state "$CONF_DIR/state.json" apply --xray-bin /usr/local/bin/xray \
    --config-out "$CONF_DIR/xray.json" --group "$SERVICE_USER" >/dev/null
  systemctl restart "$SERVICE_NAME"

  # Optional Hy2 bindDevice iface: Table=off, no DNS line, MTU 1280 (never steals default route).
  if [[ -f "$CONF_DIR/hysteria2.yaml" ]]; then
    command -v wg-quick >/dev/null || apt-get install -y -qq wireguard-tools >/dev/null
    shahrah --state "$CONF_DIR/state.json" warp wg-conf --out /etc/wireguard/warp.conf >/dev/null
    chmod 0600 /etc/wireguard/warp.conf
    if grep -q '^DNS' /etc/wireguard/warp.conf; then
      die "refusing WARP iface: wg-conf must not set DNS (would hijack host resolver)"
    fi
    if ! grep -q '^Table = off' /etc/wireguard/warp.conf; then
      die "refusing WARP iface: wg-conf must set Table = off"
    fi
    systemctl enable wg-quick@warp >/dev/null
    systemctl restart wg-quick@warp
    # Confirm host default route still via the uplink, not WARP.
    if ip -4 route show default | grep -q 'dev warp'; then
      systemctl stop wg-quick@warp || true
      die "WARP iface stole the default route; rolled back wg-quick@warp"
    fi
    shahrah --state "$CONF_DIR/state.json" hysteria2 server --out "$CONF_DIR/hysteria2.yaml" >/dev/null
    chown root:"$SERVICE_USER" "$CONF_DIR/hysteria2.yaml"
    chmod 0640 "$CONF_DIR/hysteria2.yaml"
    systemctl restart shahrah-hysteria2 || true
  fi
  log "warp egress: Google-family via Xray WireGuard outbound (no host route/DNS change)"
  [[ "$WARP_ROUTE_ALL" -eq 0 ]] || log "  WARNING: --warp-route-all is set (all egress via WARP)"
}

install_waterwall() {
  local arch expected actual dir self service="127.0.0.1:${PORT}" iran_ip exit_ip
  arch="$(arch_suffix)"
  if [[ "$arch" == amd64 ]]; then arch="x64"; expected="$WW_SHA256_X64"; else expected="$WW_SHA256_ARM64"; fi
  dir="$(mktemp -d)"
  log "downloading WaterWall ${WW_VERSION}"
  curl -fsSL --retry 3 -o "$dir/ww.zip" \
    "https://github.com/radkesvat/WaterWall/releases/download/${WW_VERSION}/Waterwall-linux-gcc-${arch}.zip"
  actual="$(sha256sum "$dir/ww.zip" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || die "checksum mismatch for WaterWall (expected $expected, got $actual)"
  unzip -q -o "$dir/ww.zip" Waterwall -d "$dir"
  install -m 0755 "$dir/Waterwall" /usr/local/bin/waterwall
  rm -rf "$dir"

  self="${WW_SELF:-$(ip -4 -o addr show dev "$(default_iface)" | awk '{split($4,a,"/"); print a[1]; exit}')}"
  [[ -n "$self" ]] || die "waterwall: cannot detect this server's IP; pass --ww-self"
  if [[ "$WW_SIDE" == iran ]]; then iran_ip="$self"; exit_ip="$WW_PEER"; else iran_ip="$WW_PEER"; exit_ip="$self"; fi
  [[ -s "$CONF_DIR/backhaul.key" ]] || log "generating $CONF_DIR/backhaul.key: copy it to the peer before installing there"
  install -d -m 0750 "$CONF_DIR/waterwall"
  shahrah waterwall-config "$WW_SIDE" --iran-ip "$iran_ip" --exit-ip "$exit_ip" \
    --key-file "$CONF_DIR/backhaul.key" --mode "$WW_MODE" --tunnel-port "$WW_TUNNEL_PORT" \
    --exit-service "$service" --cover-sni "$WW_COVER_SNI" ${WW_COVER_ADDR:+--cover-addr "$WW_COVER_ADDR"} \
    --out-dir "$CONF_DIR/waterwall" >/dev/null
  shahrah waterwall-config unit --workdir "$CONF_DIR/waterwall" > /etc/systemd/system/shahrah-waterwall.service
  if [[ "$FIREWALL" -eq 1 ]] && command -v ufw >/dev/null; then
    if [[ "$WW_SIDE" == iran ]]; then
      ufw allow 443/tcp >/dev/null
      [[ "$WW_MODE" == reverse ]] && ufw allow from "$WW_PEER" to any port "$WW_TUNNEL_PORT" proto tcp >/dev/null
    elif [[ "$WW_MODE" == direct ]]; then
      ufw allow from "$WW_PEER" to any port "$WW_TUNNEL_PORT" proto tcp >/dev/null
    fi
  fi
  systemctl daemon-reload
  systemctl enable --now shahrah-waterwall >/dev/null
  systemctl restart shahrah-waterwall
  log "waterwall ${WW_SIDE} (${WW_MODE}) up; peer ${WW_PEER}, tunnel port ${WW_TUNNEL_PORT}"
}

install_relay() {
  [[ -n "$WW_PEER" ]] || die "relay role needs --ww-peer IP (the exit)"
  [[ "$FIREWALL" -eq 0 ]] || { detect_ssh_port; ufw allow "${SSH_PORT}/tcp" >/dev/null; ufw --force enable >/dev/null; }
  # Same BBR / tcp_mtu_probing as the exit: IRAN->EXIT often has MTU 1400 overlays; without
  # probing, large TLS records (feed images, 2 MB probes) black-hole after the handshake.
  shahrah print sysctl > /etc/sysctl.d/99-shahrah.conf
  sysctl --system >/dev/null || true
  install_waterwall
  # Optional crisis path on the Iran box itself (same paqet key as the exit, or its own).
  [[ "$WITH_PAQET" -eq 0 ]] || install_paqet
  log "relay ready: users keep their exit REALITY links, pointed at this server's IP"
}

install_paqet() {
  local arch expected actual iface ip gw mac dir
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64"; expected="$PAQET_SHA256_AMD64" ;;
    aarch64|arm64) arch="arm64"; expected="$PAQET_SHA256_ARM64" ;;
    *) die "paqet: unsupported architecture: $(uname -m)" ;;
  esac
  case "$PAQET_PORT" in 80|443|53) die "paqet must not use port ${PAQET_PORT}" ;; esac
  dir="$(mktemp -d)"
  log "downloading paqet ${PAQET_VERSION}"
  curl -fsSL --retry 3 -o "$dir/paqet.tgz" \
    "https://github.com/hanselime/paqet/releases/download/${PAQET_VERSION}/paqet-linux-${arch}-${PAQET_VERSION}.tar.gz"
  actual="$(sha256sum "$dir/paqet.tgz" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || die "checksum mismatch for paqet (expected $expected, got $actual)"
  tar -xzf "$dir/paqet.tgz" -C "$dir" "paqet_linux_${arch}"
  install -m 0755 "$dir/paqet_linux_${arch}" /usr/local/bin/paqet
  rm -rf "$dir"

  iface="$(default_iface)"
  gw="$(default_gateway "$iface")"
  ip="$(ip -4 -o addr show dev "$iface" | awk '{split($4,a,"/"); print a[1]; exit}')"
  mac="$(gateway_mac "$gw" "$iface" || true)"
  [[ -n "$iface" && -n "$ip" && -n "$mac" ]] \
    || die "paqet: cannot detect interface/ip/gateway MAC (iface=${iface:-?} gw=${gw:-?}); set PAQET_ROUTER_MAC"
  shahrah paqet-config server --interface "$iface" --ip "$ip" --router-mac "$mac" \
    --port "$PAQET_PORT" --key-file "$CONF_DIR/paqet.key" --out "$CONF_DIR/paqet.yaml"
  local line
  while IFS= read -r line; do
    # idempotent: only append a rule that is not there yet (-C checks, -A appends)
    # shellcheck disable=SC2086
    ${line/ -A / -C } >/dev/null 2>&1 || $line
  done < <(shahrah paqet-config firewall --port "$PAQET_PORT")
  shahrah paqet-config unit --unit-role server --config-path "$CONF_DIR/paqet.yaml" \
    > /etc/systemd/system/shahrah-paqet.service
  systemctl daemon-reload
  systemctl enable --now shahrah-paqet >/dev/null
  log "paqet server on :${PAQET_PORT} (key: ${CONF_DIR}/paqet.key, copy it to the Iran relay)"
}

install_app() {
  log "installing shahrah from ${SRC_DIR} (with ${PYTHON_BIN})"
  "$PYTHON_BIN" -m venv "$APP_DIR/venv"
  "$APP_DIR/venv/bin/pip" install --quiet --upgrade "$SRC_DIR"
  ln -sf "$APP_DIR/venv/bin/shahrah" /usr/local/bin/shahrah
}

setup_user_and_dirs() {
  id -u "$SERVICE_USER" >/dev/null 2>&1 \
    || useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
  install -d -m 0750 -o root -g "$SERVICE_USER" "$CONF_DIR"
}

init_node() {
  local state="$CONF_DIR/state.json" extra=() spec
  [[ "$PORT" == "443" || "$PORT" == "80" || "$PORT" == "53" ]] || extra+=(--allow-non-443)
  for spec in "${EXTRA_LISTENERS[@]}"; do
    extra+=(--extra-listener "$spec")
    # A CDN origin port (e.g. 8080) is outside 443/80/53 by design.
    case "${spec%%:*}" in 443|80|53) ;; *) [[ " ${extra[*]} " == *" --allow-non-443 "* ]] || extra+=(--allow-non-443) ;; esac
  done
  if [[ -f "$state" ]]; then
    log "keeping existing node state ($state)"
  else
    log "generating REALITY keys on this machine"
    shahrah --state "$state" init --host "$HOST" --target "$TARGET" \
      --profile "$PROFILE" --port "$PORT" "${extra[@]}"
  fi
  if [[ -z "$(shahrah --state "$state" user list)" ]]; then
    shahrah --state "$state" user add first >/dev/null
  fi
  # Loopback StatsService for `shahrah usage` on independent nodes (not panel cores).
  shahrah --state "$state" stats-api 10085 >/dev/null
  shahrah --state "$state" apply --xray-bin /usr/local/bin/xray \
    --config-out "$CONF_DIR/xray.json" --group "$SERVICE_USER"
}

free_dns_port() {
  # Ubuntu/Debian run a local stub resolver on 127.0.0.53:53 which blocks binding port 53.
  if ! shahrah --state "$CONF_DIR/state.json" listener list | awk '{print $1}' | grep -qx 53; then
    return
  fi
  log "port 53 is used by a listener: disabling the systemd-resolved stub"
  if systemctl is-active --quiet systemd-resolved; then
    install -d /etc/systemd/resolved.conf.d
    printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/90-shahrah.conf
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    systemctl restart systemd-resolved
  fi
  if ss -ltnpH 'sport = :53' | grep -v '"xray"' | grep -q .; then
    die "TCP port 53 is already used by another service; stop it or drop the 53 listener"
  fi
}

install_service() {
  free_dns_port
  log "installing systemd service ${SERVICE_NAME}"
  shahrah --state "$CONF_DIR/state.json" print systemd-unit \
    > "/etc/systemd/system/${SERVICE_NAME}.service"
  shahrah --state "$CONF_DIR/state.json" print sysctl > /etc/sysctl.d/99-shahrah.conf
  sysctl --system >/dev/null || true
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null
  systemctl restart "$SERVICE_NAME"
  sleep 2
  systemctl is-active --quiet "$SERVICE_NAME" \
    || { journalctl -u "$SERVICE_NAME" -n 20 --no-pager >&2; die "$SERVICE_NAME failed to start"; }
}

install_brain() {
  log "installing the brain service"
  [[ -f "$CONF_DIR/brain.env" ]] || install -m 0640 -o root -g "$SERVICE_USER" /dev/null "$CONF_DIR/brain.env"
  if [[ ! -s "$CONF_DIR/brain.env" ]]; then
    cat > "$CONF_DIR/brain.env" <<'EOF'
# Panel owner access is NOT needed here: use the least-privilege brain key.
# Lab self-signed panels: use https://127.0.0.1:8000 and INSECURE_TLS=1 (plain http fails TLS panels).
SHAHRAH_PANEL_URL=https://127.0.0.1:8000
SHAHRAH_PANEL_API_KEY=
SHAHRAH_PANEL_INSECURE_TLS=1
# Optional burn / control vantage (paths or https URLs):
# SHAHRAH_CONTROL_REPORT=/var/lib/shahrah/control-report.json
# SHAHRAH_WRITE_REPORT=/var/www/html/shahrah-report.json
# SHAHRAH_ON_BURN=/usr/local/sbin/shahrah-on-burn
EOF
  fi
  # The service runs as $SERVICE_USER; root-only 0600 files cause PermissionError at start.
  chown root:"$SERVICE_USER" "$CONF_DIR" "$CONF_DIR/brain.env"
  chmod 0750 "$CONF_DIR"
  chmod 0640 "$CONF_DIR/brain.env"
  [[ -f "$CONF_DIR/brain.json" ]] && chown root:"$SERVICE_USER" "$CONF_DIR/brain.json" && chmod 0640 "$CONF_DIR/brain.json"
  shahrah print brain-unit > "/etc/systemd/system/shahrah-brain.service"
  systemctl daemon-reload
  systemctl enable shahrah-brain >/dev/null
  if [[ -f "$CONF_DIR/brain.json" ]]; then
    systemctl restart shahrah-brain
    sleep 2
    systemctl is-active --quiet shahrah-brain \
      || { journalctl -u shahrah-brain -n 20 --no-pager >&2; die "shahrah-brain failed to start"; }
    log "shahrah-brain started"
  else
    log "now create $CONF_DIR/brain.json (see docs/PANEL.md), fill $CONF_DIR/brain.env, then:"
    log "  chown root:${SERVICE_USER} $CONF_DIR/brain.json && chmod 640 $CONF_DIR/brain.json"
    log "  systemctl start shahrah-brain"
  fi
}

detect_ssh_port() {
  if [[ -n "$SSH_PORT" ]]; then return; fi
  if command -v sshd >/dev/null; then
    SSH_PORT="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')"
  fi
  SSH_PORT="${SSH_PORT:-22}"
}

setup_firewall() {
  [[ "$FIREWALL" -eq 1 ]] || { log "skipping firewall (--no-firewall)"; return; }
  detect_ssh_port
  log "configuring ufw (SSH ${SSH_PORT}/tcp stays open)"
  local line
  while IFS= read -r line; do
    # shellcheck disable=SC2086
    $line >/dev/null
  done < <(shahrah --state "$CONF_DIR/state.json" print ufw --ssh-port "$SSH_PORT")
}

main() {
  parse_args "$@"
  check_system
  install_packages
  install_xray
  install_app
  setup_user_and_dirs
  if [[ "$ROLE" == "brain" ]]; then
    install_brain
    return
  fi
  if [[ "$ROLE" == "relay" ]]; then
    install_relay
    return
  fi
  free_public_ports
  init_node
  install_service
  setup_firewall
  [[ "$WITH_PAQET" -eq 0 ]] || install_paqet
  [[ "$WITH_HY2" -eq 0 ]] || install_hysteria2
  [[ "$WITH_WARP" -eq 0 ]] || install_warp
  [[ -z "$WW_SIDE" ]] || install_waterwall

  log "done. Client link for user 'first' (keep it private):"
  shahrah --state "$CONF_DIR/state.json" link first
  cat <<EOF

Next steps (see docs/OPERATOR.md):
  shahrah user add NAME && shahrah apply --xray-bin /usr/local/bin/xray \\
    --config-out ${CONF_DIR}/xray.json --group ${SERVICE_USER} && systemctl restart ${SERVICE_NAME}
  # loopback subscription (secret in EnvironmentFile, never on argv):
  umask 077
  printf 'SHAHRAH_SUB_SECRET=%s\n' "\$(shahrah serve-sub --print-secret)" > ${CONF_DIR}/sub.env
  shahrah print serve-sub-unit > /etc/systemd/system/shahrah-serve-sub.service
  systemctl enable --now shahrah-serve-sub
  # size the box: shahrah capacity --users 2000 && shahrah load-test --connections 500
EOF
}

# Sourcing the script (tests) only defines the functions.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
