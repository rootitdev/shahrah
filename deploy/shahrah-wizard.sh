#!/usr/bin/env bash
# Interactive wizard — Persian status, bootstrap-safe CLI.
set -Eeuo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SHAHRAH_SRC_DIR="$SRC_DIR" SHAHRAH_APP_DIR="${SHAHRAH_APP_DIR:-/opt/shahrah}"
# shellcheck source=lib/shahrah-cli.sh
source "$SRC_DIR/deploy/lib/shahrah-cli.sh"

INSTALL="$SRC_DIR/deploy/install.sh"
UNINSTALL="$SRC_DIR/deploy/uninstall-shahrah.sh"
UPGRADE="$SRC_DIR/deploy/upgrade-shahrah.sh"
STATE="/etc/shahrah/state.json"

if [[ -n "${NO_COLOR:-}" ]] || [[ ! -t 1 ]]; then
  C_H="" C_OK="" C_ERR="" C_DIM=""
else
  C_H='\033[1;36m'
  C_OK='\033[1;32m'
  C_ERR='\033[1;31m'
  C_DIM='\033[0m'
fi

say() { printf '%b%s%b\n' "$C_H" "$*" "$C_DIM"; }
ok() { printf '%b%s%b\n' "$C_OK" "$*" "$C_DIM"; }
err() { printf '%b%s%b\n' "$C_ERR" "$*" "$C_DIM" >&2; }

need_root() {
  [[ "$(id -u)" -eq 0 ]] || { err "با sudo اجرا کنید."; return 1; }
  return 0
}

show_status() {
  if ! shahrah_cli_readonly lifecycle status --fa --src-root "$SRC_DIR" 2>/dev/null; then
    err "CLI قدیمی — فقط وضعیت از سورس ممکن نیست."
    err "قدم bootstrap (با رضایت): sudo $INSTALL --host ... --target ..."
    return 1
  fi
  return 0
}

run_install() {
  local host target target_d mp=()
  if [[ -f "$STATE" ]]; then
    say "state موجود است — host/target فقط با تأیید عوض می‌شود."
    printf 'HOST/TARGET جدید؟ [y/N]: '
    read -r ch
    if [[ ! "$ch" =~ ^[Yy] ]]; then
      host="$(python3 -c "import json;print(json.load(open('$STATE'))['public_host'])")"
      target="$(python3 -c "import json;print(json.load(open('$STATE'))['target_host'])")"
    else
      printf 'HOST: '; read -r host
      printf 'TARGET [www.cloudflare.com]: '; read -r target
      target="${target:-www.cloudflare.com}"
    fi
  else
    printf 'HOST: '; read -r host
    printf 'TARGET [www.cloudflare.com]: '; read -r target
    target="${target:-www.cloudflare.com}"
  fi
  printf 'multi-port 53 (تأثیر DNS)؟ [y/N]: '
  read -r m; [[ "$m" =~ ^[Yy] ]] && mp=(--multi-port)
  printf 'ادامه نصب؟ [y/N]: '
  read -r c
  [[ "$c" =~ ^[Yy] ]] || return 0
  set +e
  "$INSTALL" --host "$host" --target "${target:-www.cloudflare.com}" "${mp[@]}"
  local rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then ok "نصب تمام شد."; else err "نصب ناموفق (کد $rc) — سرویس قبلی معمولاً فعال می‌ماند."; fi
  show_status || true
}

run_uninstall_preview() {
  say "پیش‌نمایش حذف — هیچ فایلی پاک نمی‌شود."
  set +e
  "$UNINSTALL" --dry-run
  local rc=$?
  set -e
  [[ "$rc" -eq 0 ]] || err "پیش‌نمایش ناموفق — CLI را از سورس به‌روز کنید."
}

menu() {
  say "━━ شاهراه ━━"
  show_status 2>/dev/null || say "(وضعیت: CLI نیاز به bootstrap دارد)"
  printf '%s\n' \
    "  1) خلاصه وضعیت (همین بالا)" \
    "  2) نصب / ارتقا خروج" \
    "  3) رله WaterWall" \
    "  4) پیش‌نمایش حذف (فقط خواندن)" \
    "  5) توقف سرویس (state می‌ماند)" \
    "  6) خروج"
  printf '> '
  read -r choice
  case "$choice" in
    1) show_status || true; menu ;;
    2) run_install; menu ;;
    3)
      printf 'EXIT_PEER_IP: '; read -r peer
      printf 'ادامه؟ [y/N]: '; read -r c
      [[ "$c" =~ ^[Yy] ]] || { menu; return; }
      set +e
      "$INSTALL" --role relay --ww-peer "$peer" --no-firewall
      set -e
      menu
      ;;
    4) run_uninstall_preview; menu ;;
    5)
      printf 'توقف سرویس‌های شاهراه؟ [y/N]: '
      read -r c
      [[ "$c" =~ ^[Yy] ]] && "$UNINSTALL" --yes --stop-only
      menu
      ;;
    6) exit 0 ;;
    *) err "گزینه نامعتبر"; menu ;;
  esac
}

main() {
  need_root || exit 2
  if [[ ! -t 0 ]]; then
    err "TTY نیست —: sudo $INSTALL --host HOST --target www.cloudflare.com"
    exit 2
  fi
  menu
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
