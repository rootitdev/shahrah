#!/usr/bin/env bash
# Interactive terminal wizard (Persian). Non-TTY: use deploy/install.sh flags directly.
set -Eeuo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
  [[ "$(id -u)" -eq 0 ]] || { err "این ویزارد را با sudo اجرا کنید."; exit 2; }
}

menu() {
  say "━━ شاهراه — ویزارد ━━"
  printf '%s\n' \
    "  1) نصب / ارتقای خروج (exit)" \
    "  2) نقش رله ایران (WaterWall؛ بدون نصب Xray جدید)" \
    "  3) خروج نام‌گذاری‌شده (multi-exit)" \
    "  4) وضعیت" \
    "  5) توقف سرویس‌ها (حفظ state)" \
    "  6) پیش‌نمایش حذف" \
    "  7) ارتقا از git در /opt/shahrah" \
    "  8) خروج"
  printf '> '
  read -r choice
  case "$choice" in
    1) wizard_exit ;;
    2) wizard_relay ;;
    3) wizard_peers ;;
    4) wizard_status ;;
    5) "$UNINSTALL" --yes ;;
    6) "$UNINSTALL" --dry-run ;;
    7) "$UPGRADE" ;;
    8) exit 0 ;;
    *) err "گزینه نامعتبر"; menu ;;
  esac
}

wizard_exit() {
  say "نصب/ارتقای خروج (Xray + REALITY)"
  if [[ -f "$STATE" ]]; then
    say "state موجود — بدون تأیید، host/target عوض نمی‌شود."
    printf 'HOST/TARGET جدید می‌خواهید؟ [y/N]: '
    read -r ch
    if [[ ! "$ch" =~ ^[Yy] ]]; then
      exec "$INSTALL" --host "$(python3 -c "import json;print(json.load(open('$STATE'))['public_host'])")" \
        --target "$(python3 -c "import json;print(json.load(open('$STATE'))['target_host'])")"
    fi
  fi
  printf 'HOST: '
  read -r host
  printf 'TARGET [www.cloudflare.com]: '
  read -r target
  target="${target:-www.cloudflare.com}"
  printf 'multi-port 53 (تأثیر DNS stub)؟ [y/N]: '
  read -r mp
  local extra=()
  [[ "$mp" =~ ^[Yy] ]] && extra+=(--multi-port)
  ok "پیش‌نمایش: host=$host target=$target ${extra[*]:-}"
  printf 'ادامه؟ [y/N]: '
  read -r c
  [[ "$c" =~ ^[Yy] ]] || { menu; return; }
  exec "$INSTALL" --host "$host" --target "$target" "${extra[@]}"
}

wizard_relay() {
  say "رله ایران: WaterWall برای ورود داخلی؛ روی ایران Xray نصب/ارتقا نمی‌شود مگر قبلاً نصب شده باشد."
  if [[ -f "$STATE" ]]; then
    say "توجه: state.json از نصب قبلی هنوز روی دیسک است — این منو فقط --role relay اجرا می‌کند."
  fi
  printf 'EXIT_PEER_IP: '
  read -r peer
  ok "پیش‌نمایش: ww-peer=$peer (بدون تغییر host/target خروج)"
  printf 'ادامه؟ [y/N]: '
  read -r c
  [[ "$c" =~ ^[Yy] ]] || { menu; return; }
  exec "$INSTALL" --role relay --ww-peer "$peer" --no-firewall
}

wizard_peers() {
  say "multi-exit — کلید جدا، پورت کاربر جدا، لینک جدا"
  printf 'list | add | remove | activate: '
  read -r op
  case "$op" in
    list) shahrah relay peer-list ;;
    add)
      printf 'NAME: '; read -r name
      printf 'EXIT_IP: '; read -r exit_ip
      printf 'USER_PORT [443]: '; read -r up; up="${up:-443}"
      printf 'TUNNEL_PORT [8443]: '; read -r tp; tp="${tp:-8443}"
      printf 'IRAN_IP: '; read -r iran
      printf 'ENTRY_HOST: '; read -r entry; entry="${entry:-$iran}"
      shahrah relay peer-add --name "$name" --exit-ip "$exit_ip" --user-port "$up" \
        --tunnel-port "$tp" --iran-ip "$iran" --entry-host "$entry"
      ok "کلید: /etc/shahrah/backhaul-${name}.key را به exit کپی کنید"
      ;;
    remove)
      printf 'NAME: '; read -r name
      printf 'حذف peer و پوشه WW؟ [y/N]: '
      read -r c
      [[ "$c" =~ ^[Yy] ]] || { menu; return; }
      systemctl disable --now "shahrah-waterwall@${name}" 2>/dev/null || true
      shahrah relay peer-remove --name "$name" --purge-dir
      ;;
    activate)
      printf 'NAME: '; read -r name
      shahrah relay peer-activate --name "$name"
      printf 'دستورات ufw/systemctl بالا را اجرا کنید.\n'
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
  systemctl list-units 'shahrah-waterwall-exit@*' --no-legend 2>/dev/null | while read -r line; do ok "$line"; done
  [[ -f "$STATE" ]] && shahrah --state "$STATE" listener list 2>/dev/null || true
  printf '\n'
  menu
}

main() {
  need_root
  if [[ ! -t 0 ]]; then
    err "TTY تعاملی نیست — از deploy/install.sh یا upgrade-shahrah.sh استفاده کنید."
    exit 2
  fi
  menu
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
