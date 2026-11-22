# Shared PasarGuard URL/key for Shahrah web panels on the master host.
# shellcheck shell=bash

panel_die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

panel_load_master_secrets() {
  local secrets="${PANEL_SECRETS_FILE:-/root/.vpn-secrets/.env}"
  SHAHRAH_PANEL_URL="${SHAHRAH_PANEL_URL:-}"
  SHAHRAH_PANEL_API_KEY="${SHAHRAH_PANEL_API_KEY:-${PANEL_API_KEY:-}}"
  SHAHRAH_PANEL_INSECURE_TLS="${SHAHRAH_PANEL_INSECURE_TLS:-0}"
  if [[ -f "$secrets" ]]; then
    # shellcheck disable=SC1090
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%%#*}"
      [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
      key="${line%%=*}"
      val="${line#*=}"
      case "$key" in
        SHAHRAH_PANEL_URL|PANEL_URL|PASARGUARD_URL|MASTER_PANEL_URL)
          [[ -z "$SHAHRAH_PANEL_URL" ]] && SHAHRAH_PANEL_URL="${val//\"/}"
          ;;
        SHAHRAH_PANEL_API_KEY|PANEL_API_KEY|PASARGUARD_API_KEY)
          [[ -z "$SHAHRAH_PANEL_API_KEY" ]] && SHAHRAH_PANEL_API_KEY="${val//\"/}"
          ;;
        SHAHRAH_PANEL_INSECURE_TLS) SHAHRAH_PANEL_INSECURE_TLS="${val//\"/}" ;;
      esac
    done <"$secrets"
  fi
  export SHAHRAH_PANEL_URL SHAHRAH_PANEL_API_KEY SHAHRAH_PANEL_INSECURE_TLS
}

panel_api_config_extra() {
  # Appended to deploy/panels config.env via PANEL_CFG_EXTRA
  local lines=()
  [[ -n "${SHAHRAH_PANEL_URL:-}" ]] || return 0
  lines+=("PANEL_API_BASE=${SHAHRAH_PANEL_URL}")
  lines+=("REMOTE_PANEL_URL=${SHAHRAH_PANEL_URL}")
  lines+=("MASTER_PANEL_URL=${SHAHRAH_PANEL_URL}")
  if [[ -n "${SHAHRAH_PANEL_INSECURE_TLS:-}" ]]; then
    lines+=("PANEL_INSECURE_TLS=${SHAHRAH_PANEL_INSECURE_TLS}")
  fi
  printf '%s\n' "${lines[@]}"
}