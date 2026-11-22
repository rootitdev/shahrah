#!/bin/bash
# نصب path-web (انتخاب مسیر بک‌هال شاهراه)
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../lib/panel_install_lib.sh
source "$DIR/../lib/panel_install_lib.sh"

panel_need_root

LIB=/usr/local/lib/path-web
ETC=/etc/path-web
SECRETS=/root/.vpn-secrets/path-web.env
LISTEN="${LISTEN:-}"
AUTH_USER="${AUTH_USER:-}"
AUTH_PASS="${AUTH_PASS:-}"
PANEL_BASE="${PANEL_BASE:-}"
KEEP_AUTH=0

[[ -f "$DIR/app.py" ]] || { echo "app.py missing" >&2; exit 2; }

echo "=== نصب path-web (مسیر بک‌هال) ==="

panel_prompt PANEL_BASE "آدرس عمومی پنل (بدون اسلش آخر)" "https://panel.example.com:2096"
PANEL_BASE="$(panel_normalize_base "$PANEL_BASE")"
panel_prompt AUTH_USER "نام کاربری" "path"
panel_prompt LISTEN "listen داخلی" "127.0.0.1:8791"

if [[ -z "${AUTH_PASS}" && -f "$ETC/admin.pass" ]]; then
  AUTH_PASS="$(cat "$ETC/admin.pass")"
  KEEP_AUTH=1
fi
panel_prompt_secret AUTH_PASS "رمز"
[[ -n "${AUTH_PASS}" ]] || AUTH_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"

install -d -m 755 "$LIB"
install -d -m 700 "$ETC"
install -m 644 "$DIR/app.py" "$LIB/"
install -m 644 "$DIR/path-web.service" /etc/systemd/system/path-web.service

export PANEL_CFG="$ETC/config.env"
export PANEL_LISTEN="$LISTEN"
export PANEL_USER="$AUTH_USER"
export PANEL_PASS="$AUTH_PASS"
export PANEL_COOKIE="shahpath"
export PANEL_KEEP="$KEEP_AUTH"
export PANEL_CFG_EXTRA='SHAHRAH_BIN=/usr/local/bin/shahrah'
panel_write_auth_config
AUTH_USER="$(tr -d '\n' < "$ETC/.user.tmp")"
rm -f "$ETC/.user.tmp"

panel_save_creds "$ETC" "$AUTH_USER" "$AUTH_PASS" "$SECRETS" \
  "URL=${PANEL_BASE}/path/" \
  "PANEL_BASE=${PANEL_BASE}"

panel_nginx_maybe "/path/" "http://${LISTEN}/"
panel_finish path-web.service "${PANEL_BASE}/path/" "$ETC/admin.pass"