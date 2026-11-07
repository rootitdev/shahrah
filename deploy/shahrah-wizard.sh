#!/usr/bin/env bash
# Interactive terminal wizard (Persian). Non-TTY: use deploy/install.sh flags directly.
set -Eeuo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL="$SRC_DIR/deploy/install.sh"
UNINSTALL="$SRC_DIR/deploy/uninstall-shahrah.sh"

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
  [[ "$(id -u)" -eq 0 ]] || { err "این ویزارد را با sudo اجرا کنید."; exit 2; }
}

menu() {
  say "━━ شاهراه — ویزارد نصب ━━"
  printf '%s\n' \
    "  1) نصب / ارتقای خروج (exit)" \
    "  2) نصب رله ایران (WaterWall)" \
    "  3) مدیریت خروج‌های نام‌گذاری‌شده (multi-exit)" \
    "  4) وضعیت سرویس‌ها" \
    "  5) پیش‌نمایش حذف (dry-run)" \
    "  6) خروج"
  printf '> '
  read -r choice
  case "$choice" in
    1) wizard_exit ;;
    2) wizard_relay ;;
    3) wizard_peers ;;
    4) wizard_status ;;
    5) "$UNINSTALL" --dry-run ;;
    6) exit 0 ;;
    *) err "گزینه نامعتبر"; menu ;;
  esac
}

wizard_exit() {
  say "نصب خروج — IP یا دامنه عمومی و target REALITY"
  printf 'HOST (مثال 198.51.100.221 یا vpn.example.com): '
  read -r host
  printf 'TARGET (پیش‌فرض www.cloudflare.com): '
  read -r target
  target="${target:-www.cloudflare.com}"
  printf 'multi-port 53 هم اضافه شود؟ [y/N]: '
  read -r mp
  local extra=()
  [[ "$mp" =~ ^[Yy] ]] && extra+=(--multi-port)
  ok "پیش‌نمایش: host=$host target=$target ${extra[*]:-}"
  printf 'ادامه؟ [y/N]: '
  read -r c
  [[ "$c" =~ ^[Yy] ]] || return 0
  exec "$INSTALL" --host "$host" --target "$target" "${extra[@]}"
}

wizard_relay() {
  say "رله ایران — فقط WaterWall (بدون Xray روی ایران)"
  printf 'EXIT_PEER_IP (مثال آلمان): '
  read -r peer
  ok "پیش‌نمایش: ww-peer=$peer"
  exec "$INSTALL" --role relay --ww-peer "$peer" --no-firewall
}

wizard_peers() {
  say "خروج‌های چندگانه — هر نام یک تونل جدا (کلید/کاربر روی همان exit)"
  printf 'عملیات (list | add | remove | render): '
  read -r op
  case "$op" in
    list) shahrah relay peer-list ;;
    add)
      printf 'NAME (مثال de): '; read -r name
      printf 'EXIT_IP: '; read -r exit_ip
      printf 'USER_PORT روی ایران [443]: '; read -r up
      up="${up:-443}"
      printf 'TUNNEL_PORT [8443]: '; read -r tp
      tp="${tp:-8443}"
      printf 'IRAN_PUBLIC_IP: '; read -r iran
      printf 'ENTRY_HOST (همان IP/دامنه‌ای که کلاینت می‌زند): '; read -r entry
      shahrah relay peer-add --name "$name" --exit-ip "$exit_ip" --user-port "$up" \
        --tunnel-port "$tp" --iran-ip "$iran" --entry-host "$entry"
      ok "روی exit: shahrah link USER --entry-host $entry --entry-port $up"
      ;;
    remove)
      printf 'NAME: '; read -r name
      shahrah relay peer-remove --name "$name" --purge-dir
      ;;
    render)
      printf 'NAME: '; read -r name
      shahrah relay peer-render --name "$name"
      ok "سپس: systemctl enable --now shahrah-waterwall@${name}"
      ;;
    *) err "نامعتبر" ;;
  esac
  printf '\n'
  menu
}

wizard_status() {
  for u in shahrah-xray shahrah-waterwall; do
    if systemctl is-active --quiet "$u" 2>/dev/null; then ok "$u: active"; else say "$u: inactive"; fi
  done
  systemctl list-units 'shahrah-waterwall@*' --no-legend 2>/dev/null | while read -r line; do ok "$line"; done
  if [[ -f /etc/shahrah/state.json ]]; then
    say "listeners:"
    shahrah --state /etc/shahrah/state.json listener list 2>/dev/null || true
  fi
  printf '\n'
  menu
}

main() {
  need_root
  if [[ ! -t 0 ]]; then
    err "ترمینال تعاملی نیست — از deploy/install.sh با فلگ‌ها استفاده کنید."
    exit 2
  fi
  menu
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
