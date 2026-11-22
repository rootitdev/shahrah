#!/usr/bin/env bash
# Install the Shahrah rootit portal (PasarGuard subscription recovery).
#
# This is intentionally separate from deploy/install.sh (VPN node installer):
# rootit should sit on a resilient domain that can stay up when the subscription
# domain dies. It talks to PasarGuard over the panel API.
#
#   sudo ./deploy/install-rootit.sh \
#     --panel-url https://panel.example.com:8000 \
#     --public-host sub.example.com \
#     --public-port 2096 \
#     --api-key 'pg_key_...'
#
# Then put TLS (Caddy/nginx) in front of 127.0.0.1:8790 and announce
# https://rootit.example.com/mysub in your Telegram channel.
set -Eeuo pipefail

APP_DIR="/opt/shahrah"
CONF_DIR="/etc/shahrah"
SERVICE_USER="shahrah"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PANEL_URL=""
PUBLIC_HOST=""
PUBLIC_PORT="2096"
PUBLIC_SCHEME="https"
API_KEY=""
REQUIRE_PASSWORD=0
LISTEN="127.0.0.1:8790"

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: install-rootit.sh --panel-url URL --public-host HOST --api-key KEY [options]

  --panel-url URL       PasarGuard panel base (API), e.g. https://panel.example.com:8000
  --public-host HOST    Public subscription hostname users should use after rotation
  --public-port PORT    Public subscription port (default 2096)
  --public-scheme SCH   https (default) or http
  --api-key KEY         PasarGuard X-Api-Key (stored in /etc/shahrah/rootit.env)
  --require-password    Enable local PIN gate (default: off — emergency username-only)
  --listen ADDR:PORT    Bind address (default 127.0.0.1:8790)
  -h, --help            Show help
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --panel-url) PANEL_URL="${2:?}"; shift 2 ;;
      --public-host) PUBLIC_HOST="${2:?}"; shift 2 ;;
      --public-port) PUBLIC_PORT="${2:?}"; shift 2 ;;
      --public-scheme) PUBLIC_SCHEME="${2:?}"; shift 2 ;;
      --api-key) API_KEY="${2:?}"; shift 2 ;;
      --require-password) REQUIRE_PASSWORD=1; shift ;;
      --listen) LISTEN="${2:?}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  [[ -n "$PANEL_URL" ]] || die "--panel-url is required"
  [[ -n "$PUBLIC_HOST" ]] || die "--public-host is required"
  [[ -n "$API_KEY" ]] || die "--api-key is required"
}

main() {
  parse_args "$@"
  [[ "$(id -u)" -eq 0 ]] || die "run as root"

  if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    log "creating system user ${SERVICE_USER}"
    useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
  fi

  install -d -m 0750 -o root -g "$SERVICE_USER" "$CONF_DIR"
  install -d -m 0755 "$APP_DIR"

  if [[ ! -x "$APP_DIR/venv/bin/shahrah" ]]; then
    log "installing shahrah into ${APP_DIR}/venv"
    python3 -m venv "$APP_DIR/venv"
    "$APP_DIR/venv/bin/pip" install --quiet --upgrade "$SRC_DIR"
    ln -sfn "$APP_DIR/venv/bin/shahrah" /usr/local/bin/shahrah
  else
    log "upgrading shahrah"
    "$APP_DIR/venv/bin/pip" install --quiet --upgrade "$SRC_DIR"
  fi

  umask 077
  printf 'SHAHRAH_PANEL_API_KEY=%s\n' "$API_KEY" >"$CONF_DIR/rootit.env"
  chown root:"$SERVICE_USER" "$CONF_DIR/rootit.env"
  chmod 0640 "$CONF_DIR/rootit.env"

  INIT_FLAGS=(--config "$CONF_DIR/rootit.json" --panel-url "$PANEL_URL"
    --public-host "$PUBLIC_HOST" --public-port "$PUBLIC_PORT" --public-scheme "$PUBLIC_SCHEME" --force)
  [[ "$REQUIRE_PASSWORD" -eq 0 ]] || INIT_FLAGS+=(--require-password)
  log "writing rootit config"
  INIT_OUT="$(shahrah rootit init "${INIT_FLAGS[@]}")"
  printf '%s\n' "$INIT_OUT"
  # rootit rewrites pins at runtime — the service user must own the file.
  chown "$SERVICE_USER:$SERVICE_USER" "$CONF_DIR/rootit.json"
  chmod 0640 "$CONF_DIR/rootit.json"

  log "installing systemd unit"
  # Rewrite listen in the unit by sed on the generated template.
  shahrah print rootit-unit | sed "s|127.0.0.1:8790|${LISTEN}|g" \
    >/etc/systemd/system/shahrah-rootit.service
  systemctl daemon-reload
  systemctl enable --now shahrah-rootit

  ADMIN_TOKEN="$(printf '%s\n' "$INIT_OUT" | awk -F= '/^admin_token=/{print $2; exit}')"
  cat <<EOF

Rootit is up on ${LISTEN} (put TLS in front).

  User page : https://${PUBLIC_HOST}/mysub   (via your reverse proxy)
  Admin     : https://${PUBLIC_HOST}/admin
  Admin token (save it): ${ADMIN_TOKEN}

When the subscription domain dies:
  1) Point DNS / TLS for a working host at this portal (or keep rootit on its own domain)
  2) shahrah rootit set-base --host NEW_HOST --port NEW_PORT
  3) Announce the rootit /mysub URL in your channel — users fetch their PasarGuard link

Optional PIN gate:
  shahrah rootit set-auth --require-password
  shahrah rootit set-pin USER PASS
EOF
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
