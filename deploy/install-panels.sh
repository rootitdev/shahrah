#!/usr/bin/env bash
# Shahrah native web panels under deploy/panels/ (no external vpn-infra-kit checkout).
#
# Roles (INSTALL_ROLE=master|relay|exit|auto|full):
#   master — settle, pay, mysub (rootit)  [PasarGuard API on this host or URL]
#   relay  — path-web, sni-watch
#   exit   — ig-mult, sni-watch (optional)
#
# Usage:
#   sudo INSTALL_ROLE=master PANEL_BASE=https://panel.example.com ./deploy/install-panels.sh
#   sudo INSTALL_ROLE=relay  PANEL_BASE=... PANELS=path,watch ./deploy/install-panels.sh
#
# Env: PANEL_BASE, PANELS, PANEL_NGINX_APPLY, LISTEN_* , ACCESS_LOG,
#      SHAHRAH_PANEL_URL, SHAHRAH_PANEL_API_KEY (or /root/.vpn-secrets/.env)
#      ROOTIT_PUBLIC_HOST, ROOTIT_PUBLIC_PORT (mysub on master)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PANELS_DIR="$SCRIPT_DIR/panels"

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "run as root (sudo)"
[[ -d "$PANELS_DIR/lib" ]] || die "missing $PANELS_DIR"

# shellcheck source=lib/panel_master_env.sh
source "$SCRIPT_DIR/lib/panel_master_env.sh"
panel_load_master_secrets
PANEL_CFG_EXTRA_API="$(panel_api_config_extra || true)"
export PANEL_CFG_EXTRA_API SHAHRAH_PANEL_URL SHAHRAH_PANEL_API_KEY SHAHRAH_PANEL_INSECURE_TLS

resolve_install_role() {
  case "${INSTALL_ROLE:-auto}" in
    master|relay|exit|full) echo "${INSTALL_ROLE}"; return ;;
    auto) ;;
    *) die "INSTALL_ROLE must be master, relay, exit, auto, or full";;
  esac
  if systemctl is-active shahrah-waterwall 2>/dev/null | grep -qx active; then
    if [[ ! -s /etc/shahrah/state.json ]] 2>/dev/null; then
      echo relay
      return
    fi
  fi
  if systemctl is-active shahrah-xray 2>/dev/null | grep -qx active; then
    echo exit
    return
  fi
  echo master
}

ROLE="$(resolve_install_role)"
case "$ROLE" in
  master) DEFAULT_PANELS="settle,mysub" ;;
  relay) DEFAULT_PANELS="path,watch" ;;
  exit) DEFAULT_PANELS="ig,watch" ;;
  full) DEFAULT_PANELS="ig,settle,watch,path,mysub" ;;
esac

PANEL_BASE="${PANEL_BASE:-}"
[[ -n "$PANEL_BASE" ]] || die "set PANEL_BASE=https://panel.example.com"
PANEL_BASE="${PANEL_BASE%/}"

PANELS_CSV="${PANELS:-$DEFAULT_PANELS}"
log "install_role=$ROLE panels=$PANELS_CSV"

PANEL_NGINX_APPLY="${PANEL_NGINX_APPLY:-n}"
LISTEN_IG="${LISTEN_IG:-127.0.0.1:8786}"
LISTEN_SETTLE="${LISTEN_SETTLE:-127.0.0.1:8789}"
LISTEN_WATCH="${LISTEN_WATCH:-127.0.0.1:8785}"
LISTEN_PATH="${LISTEN_PATH:-127.0.0.1:8791}"
LISTEN_MYSUB="${LISTEN_MYSUB:-127.0.0.1:8790}"
ACCESS_LOG="${ACCESS_LOG:-/var/log/shahrah/access.log}"

want() { [[ ",${PANELS_CSV}," == *",${1},"* ]]; }

run_panel() {
  local dir="$1"
  [[ -f "$dir/install.sh" ]] || die "missing $dir/install.sh"
  log "installing $(basename "$dir")"
  (
    cd "$dir"
    export PANEL_BASE PANEL_NGINX_APPLY PANEL_CFG_EXTRA_API
    bash install.sh </dev/null
  )
}

install_mysub() {
  local api="${SHAHRAH_PANEL_API_KEY:-${PANEL_API_KEY:-}}"
  local panel_url="${SHAHRAH_PANEL_URL:-}"
  [[ -n "$panel_url" ]] || die "mysub needs SHAHRAH_PANEL_URL (master PasarGuard API base)"
  [[ -n "$api" ]] || die "mysub needs SHAHRAH_PANEL_API_KEY or PANEL_API_KEY"
  local pub_host="${ROOTIT_PUBLIC_HOST:-}"
  if [[ -z "$pub_host" ]]; then
    pub_host="$(python3 -c "from urllib.parse import urlparse; print(urlparse('${PANEL_BASE}').hostname or '')")"
  fi
  [[ -n "$pub_host" ]] || die "set ROOTIT_PUBLIC_HOST or use a PANEL_BASE with a hostname"
  ROOTIT_PUBLIC_PORT="${ROOTIT_PUBLIC_PORT:-2096}"
  log "installing mysub (shahrah rootit) public_host=$pub_host"
  "$SCRIPT_DIR/install-rootit.sh" \
    --panel-url "$panel_url" \
    --public-host "$pub_host" \
    --public-port "$ROOTIT_PUBLIC_PORT" \
    --api-key "$api" \
    --listen "$LISTEN_MYSUB"
}

caddy_snippet() {
  cat <<EOF

# --- Shahrah panels (${ROLE}) ---
EOF
  want ig && cat <<EOF
handle_path /ig/* { reverse_proxy ${LISTEN_IG} }
handle /ig { redir /ig/ permanent }
EOF
  want settle && cat <<EOF
handle_path /settle/* { reverse_proxy ${LISTEN_SETTLE} }
handle /settle { redir /settle/ permanent }
handle_path /pay/* { reverse_proxy ${LISTEN_SETTLE}/pay/ }
handle /pay { redir /pay/ permanent }
EOF
  want watch && cat <<EOF
handle_path /watch/* { reverse_proxy ${LISTEN_WATCH} }
handle /watch { redir /watch/ permanent }
EOF
  want path && cat <<EOF
handle_path /path/* { reverse_proxy ${LISTEN_PATH} }
handle /path { redir /path/ permanent }
EOF
  want mysub && cat <<EOF
handle_path /mysub/* { reverse_proxy ${LISTEN_MYSUB} }
handle /mysub { redir /mysub/ permanent }
handle_path /admin/* { reverse_proxy ${LISTEN_MYSUB} }
EOF
  echo "# --- end shahrah panels ---"
}

nginx_snippet() {
  # shellcheck source=panels/lib/panel_install_lib.sh
  source "$PANELS_DIR/lib/panel_install_lib.sh"
  local args=()
  want ig && args+=("/ig/" "http://${LISTEN_IG}/")
  want settle && args+=("/settle/" "http://${LISTEN_SETTLE}/" "/pay/" "http://${LISTEN_SETTLE}/pay/")
  want watch && args+=("/watch/" "http://${LISTEN_WATCH}/")
  want path && args+=("/path/" "http://${LISTEN_PATH}/")
  want mysub && args+=("/mysub/" "http://${LISTEN_MYSUB}/" "/admin/" "http://${LISTEN_MYSUB}/")
  panel_nginx_snippet "${args[@]}"
}

if want settle || want mysub; then
  if [[ -z "${SHAHRAH_PANEL_API_KEY:-}" && -z "${PANEL_API_KEY:-}" ]]; then
    if [[ ! -f /root/.vpn-secrets/.env ]] || ! grep -qE '^(PANEL_API_KEY|PASARGUARD_API_KEY|SHAHRAH_PANEL_API_KEY)=' /root/.vpn-secrets/.env 2>/dev/null; then
      warn "no panel API key — settle/pay and mysub need PANEL_API_KEY in /root/.vpn-secrets/.env"
    fi
  else
    install -d -m 700 /root/.vpn-secrets
    KEY="${PANEL_API_KEY:-${SHAHRAH_PANEL_API_KEY}}"
    if [[ ! -f /root/.vpn-secrets/.env ]] || ! grep -qE '^(PANEL_API_KEY|SHAHRAH_PANEL_API_KEY)=' /root/.vpn-secrets/.env 2>/dev/null; then
      umask 077
      printf 'PANEL_API_KEY=%s\nSHAHRAH_PANEL_URL=%s\n' "$KEY" "${SHAHRAH_PANEL_URL:-}" >>/root/.vpn-secrets/.env
      chmod 600 /root/.vpn-secrets/.env
    fi
  fi
fi

warn_wrong_role() {
  local p="$1" expected="$2"
  [[ "$ROLE" == "full" ]] && return
  [[ "$ROLE" == "$expected" ]] && return
  warn "panel $p on role=$ROLE — recommended on $expected (override with INSTALL_ROLE=full)"
}

INSTALLED=()

if want ig; then
  warn_wrong_role ig exit
  export LISTEN="$LISTEN_IG"
  export AUTH_USER="${AUTH_USER_IG:-ig}"
  export AUTH_PASS="${AUTH_PASS_IG:-}"
  run_panel "$PANELS_DIR/ig-mult-web"
  INSTALLED+=("ig → ${PANEL_BASE}/ig/")
fi

if want settle; then
  warn_wrong_role settle master
  export LISTEN="$LISTEN_SETTLE"
  export AUTH_USER="${AUTH_USER_SETTLE:-settle}"
  export AUTH_PASS="${AUTH_PASS_SETTLE:-}"
  run_panel "$PANELS_DIR/settle-web"
  INSTALLED+=("settle → ${PANEL_BASE}/settle/ + /pay/")
fi

if want path; then
  warn_wrong_role path relay
  export LISTEN="$LISTEN_PATH"
  export AUTH_USER="${AUTH_USER_PATH:-path}"
  export AUTH_PASS="${AUTH_PASS_PATH:-}"
  run_panel "$PANELS_DIR/path-web"
  INSTALLED+=("path → ${PANEL_BASE}/path/")
fi

if want watch; then
  warn_wrong_role watch "relay or exit"
  if [[ ! -f "$ACCESS_LOG" ]]; then
    warn "ACCESS_LOG missing — run: shahrah access-log $ACCESS_LOG && apply && restart xray"
    install -d -m 755 "$(dirname "$ACCESS_LOG")"
    : >>"$ACCESS_LOG" || true
  fi
  export LISTEN="$LISTEN_WATCH"
  export AUTH_USER="${AUTH_USER_WATCH:-watch}"
  export AUTH_PASS="${AUTH_PASS_WATCH:-}"
  export ACCESS_LOG
  run_panel "$PANELS_DIR/sni-watch"
  INSTALLED+=("watch → ${PANEL_BASE}/watch/")
fi

if want mysub; then
  warn_wrong_role mysub master
  install_mysub
  INSTALLED+=("mysub → ${PANEL_BASE}/mysub/ (rootit ${LISTEN_MYSUB})")
fi

[[ ${#INSTALLED[@]} -gt 0 ]] || die "nothing to install (PANELS=$PANELS_CSV role=$ROLE)"

log "done"
for line in "${INSTALLED[@]}"; do echo "  $line"; done
echo
echo "===== Caddy snippet ====="
caddy_snippet
echo "===== nginx snippet ====="
nginx_snippet
echo "See docs/PANELS.md and docs/TOPOLOGY-MASTER.md"