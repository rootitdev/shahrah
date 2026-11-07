#!/usr/bin/env bash
# Install optional vpn-infra-kit web UIs vendored under deploy/panels/:
#   /ig/     — Instagram traffic multiplier (Exit, beside PasarGuard)
#   /settle/ — sales / settlement + /pay/ (Exit)
#   /watch/  — SNI watch UI (node with Xray access.log; often Iran)
#
# Not installed: path-web (use `shahrah ops` for service status).
#
# Usage:
#   sudo PANEL_BASE=https://panel.example.com:2096 ./deploy/install-panels.sh
#   sudo PANEL_BASE=... PANELS=ig,settle ./deploy/install-panels.sh
#   sudo PANEL_BASE=... PANELS=watch ACCESS_LOG=/var/log/shahrah/access.log ./deploy/install-panels.sh
#
# Env:
#   PANEL_BASE          required public panel origin (no trailing slash)
#   PANELS              comma list: ig,settle,watch (default: all three)
#   PANEL_NGINX_APPLY   y|n (default n) — pass through to panel installers
#   LISTEN_IG           default 127.0.0.1:8786  (avoids serve-sub :8788)
#   LISTEN_SETTLE       default 127.0.0.1:8789
#   LISTEN_WATCH        default 127.0.0.1:8785  (avoids shahrah ops :8787)
#   AUTH_USER_IG / AUTH_PASS_IG / AUTH_USER_SETTLE / AUTH_PASS_SETTLE /
#   AUTH_USER_WATCH / AUTH_PASS_WATCH
#   ACCESS_LOG          for watch (default: /var/log/shahrah/access.log)
set -euo pipefail

PANELS_DIR="$(cd "$(dirname "$0")/panels" && pwd)"

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "run as root (sudo)"
if [[ "${SHAHRAH_BETA:-0}" == 1 ]]; then
  warn "SHAHRAH_BETA=1: sales panels (settle/ig) are not recommended; use PANELS= or PANELS=watch only"
fi
[[ -d "$PANELS_DIR/lib" ]] || die "missing $PANELS_DIR (vendored panels)"

PANEL_BASE="${PANEL_BASE:-}"
[[ -n "$PANEL_BASE" ]] || die "set PANEL_BASE=https://panel.example.com:2096"
PANEL_BASE="${PANEL_BASE%/}"

PANELS_CSV="${PANELS:-ig,settle,watch}"
PANEL_NGINX_APPLY="${PANEL_NGINX_APPLY:-n}"
LISTEN_IG="${LISTEN_IG:-127.0.0.1:8786}"
LISTEN_SETTLE="${LISTEN_SETTLE:-127.0.0.1:8789}"
LISTEN_WATCH="${LISTEN_WATCH:-127.0.0.1:8785}"
ACCESS_LOG="${ACCESS_LOG:-/var/log/shahrah/access.log}"

want() {
  local name="$1"
  [[ ",${PANELS_CSV}," == *",${name},"* ]]
}

run_panel() {
  local dir="$1"
  [[ -f "$dir/install.sh" ]] || die "missing $dir/install.sh"
  log "installing $(basename "$dir")"
  (
    cd "$dir"
    export PANEL_BASE PANEL_NGINX_APPLY
    bash install.sh </dev/null
  )
}

caddy_snippet() {
  cat <<EOF

# --- Shahrah kit panels (paste into panel.example.com site block) ---
handle_path /ig/* {
	reverse_proxy ${LISTEN_IG}
}
handle /ig {
	redir /ig/ permanent
}
handle_path /settle/* {
	reverse_proxy ${LISTEN_SETTLE}
}
handle /settle {
	redir /settle/ permanent
}
handle_path /pay/* {
	reverse_proxy ${LISTEN_SETTLE}/pay/
}
handle /pay {
	redir /pay/ permanent
}
handle_path /watch/* {
	reverse_proxy ${LISTEN_WATCH}
}
handle /watch {
	redir /watch/ permanent
}
# --- end kit panels ---
EOF
}

nginx_snippet() {
  # shellcheck source=panels/lib/panel_install_lib.sh
  source "$PANELS_DIR/lib/panel_install_lib.sh"
  panel_nginx_snippet \
    "/ig/" "http://${LISTEN_IG}/" \
    "/settle/" "http://${LISTEN_SETTLE}/" \
    "/pay/" "http://${LISTEN_SETTLE}/pay/" \
    "/watch/" "http://${LISTEN_WATCH}/"
}

# Settle needs PasarGuard API for /pay/ auto-credit
if want settle; then
  if [[ ! -f /root/.vpn-secrets/.env ]] || ! grep -qE '^(PANEL_API_KEY|PASARGUARD_API_KEY)=' /root/.vpn-secrets/.env 2>/dev/null; then
    if [[ -z "${SHAHRAH_PANEL_API_KEY:-}" && -z "${PANEL_API_KEY:-}" ]]; then
      warn "no PANEL_API_KEY in /root/.vpn-secrets/.env (and SHAHRAH_PANEL_API_KEY unset); /pay/ auto-credit may not work until you add it"
    else
      install -d -m 700 /root/.vpn-secrets
      KEY="${PANEL_API_KEY:-${SHAHRAH_PANEL_API_KEY}}"
      if [[ ! -f /root/.vpn-secrets/.env ]]; then
        umask 077
        printf 'PANEL_API_KEY=%s\n' "$KEY" >/root/.vpn-secrets/.env
        chmod 600 /root/.vpn-secrets/.env
        log "wrote PANEL_API_KEY to /root/.vpn-secrets/.env"
      elif ! grep -qE '^(PANEL_API_KEY|PASARGUARD_API_KEY)=' /root/.vpn-secrets/.env; then
        umask 077
        printf '\nPANEL_API_KEY=%s\n' "$KEY" >>/root/.vpn-secrets/.env
        log "appended PANEL_API_KEY to /root/.vpn-secrets/.env"
      fi
    fi
  fi
fi

INSTALLED=()

if want ig; then
  export LISTEN="$LISTEN_IG"
  export AUTH_USER="${AUTH_USER_IG:-ig}"
  export AUTH_PASS="${AUTH_PASS_IG:-}"
  run_panel "$PANELS_DIR/ig-mult-web"
  INSTALLED+=("ig → ${PANEL_BASE}/ig/  (listen ${LISTEN_IG}, pass /etc/ig-mult-web/admin.pass)")
fi

if want settle; then
  export LISTEN="$LISTEN_SETTLE"
  export AUTH_USER="${AUTH_USER_SETTLE:-settle}"
  export AUTH_PASS="${AUTH_PASS_SETTLE:-}"
  run_panel "$PANELS_DIR/settle-web"
  INSTALLED+=("settle → ${PANEL_BASE}/settle/  + ${PANEL_BASE}/pay/  (listen ${LISTEN_SETTLE}, pass /etc/settle-web/admin.pass)")
fi

if want watch; then
  if [[ ! -f "$ACCESS_LOG" ]]; then
    warn "ACCESS_LOG missing ($ACCESS_LOG) — enable Xray access log before watch is useful"
    install -d -m 755 "$(dirname "$ACCESS_LOG")"
    : >>"$ACCESS_LOG" || true
  fi
  export LISTEN="$LISTEN_WATCH"
  export AUTH_USER="${AUTH_USER_WATCH:-watch}"
  export AUTH_PASS="${AUTH_PASS_WATCH:-}"
  export ACCESS_LOG
  run_panel "$PANELS_DIR/sni-watch"
  INSTALLED+=("watch → ${PANEL_BASE}/watch/  (listen ${LISTEN_WATCH}, pass /etc/sni-watch/admin.pass, log $ACCESS_LOG)")
fi

[[ ${#INSTALLED[@]} -gt 0 ]] || die "nothing to install (PANELS=$PANELS_CSV)"

log "done"
for line in "${INSTALLED[@]}"; do
  echo "  $line"
done
echo
echo "Service status is NOT these panels — use: shahrah ops  (default 127.0.0.1:8787)"
echo
echo "===== Caddy snippet ====="
caddy_snippet
echo "===== nginx snippet ====="
nginx_snippet
echo "===== end ====="
echo
echo "See docs/PANELS.md"
