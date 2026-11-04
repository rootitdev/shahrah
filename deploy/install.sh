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
WORK_DIR=""
trap '[[ -z "$WORK_DIR" ]] || rm -rf "$WORK_DIR"' EXIT

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: install.sh --host HOST [options]      (VPN exit/entry node)
       install.sh --role brain               (health prober + panel steering)

  --role ROLE       node (default) or brain
  --host HOST       public domain or IP address clients connect to (node only, required)
  --target DOMAIN   TLS 1.3 site REALITY imitates (default: www.cloudflare.com)
  --profile NAME    reality-vision (default) or reality-xhttp
  --port PORT       listen port (default 443; other ports weaken allowlist survival)
  --extra-listener PORT:PROFILE
                    additional listening port, repeatable (e.g. 80:reality-xhttp, or a CDN origin\n                    8080:cdn-xhttp:cdn.example.com[:PATH[:http]])
  --multi-port      preset: also listen on 80 and 53 with reality-xhttp (443 + 80 + 53)
  --ssh-port PORT   SSH port kept open in the firewall (default: auto-detect, else 22)
  --no-firewall     do not touch ufw
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
      --multi-port) EXTRA_LISTENERS+=("80:reality-xhttp" "53:reality-xhttp"); shift ;;
      --ssh-port) SSH_PORT="${2:?--ssh-port needs a value}"; shift 2 ;;
      --no-firewall) FIREWALL=0; shift ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; die "unknown option: $1" ;;
    esac
  done
  case "$ROLE" in
    node) [[ -n "$HOST" ]] || { usage >&2; die "--host is required for a node"; } ;;
    brain) ;;
    *) die "--role must be node or brain" ;;
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
  apt-get install -y -qq python3 python3-venv unzip curl ca-certificates ufw >/dev/null
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
  free_public_ports
  init_node
  install_service
  setup_firewall

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

main "$@"
