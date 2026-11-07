#!/usr/bin/env bash
# Roll back side effects from deploy/install.sh port-cleanup (not full uninstall).
#
# Restores systemd enablement recorded in /var/lib/shahrah/preinstall.snapshot,
# stops Shahrah units, and leaves Xray keys in /etc/shahrah for a human decision.
#
# Usage: sudo ./deploy/rollback-install.sh [--purge-config]
set -euo pipefail

CONF_DIR="/etc/shahrah"
SNAP="/var/lib/shahrah/preinstall.snapshot"
PURGE=0

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge-config) PURGE=1; shift ;;
    -h|--help)
      echo "Usage: sudo $0 [--purge-config]"
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "run as root (sudo)"

for unit in shahrah-xray shahrah-brain shahrah-serve-sub shahrah-paqet shahrah-hysteria2; do
  if systemctl list-unit-files "$unit.service" 2>/dev/null | grep -q "$unit.service"; then
    systemctl stop "$unit" 2>/dev/null || true
    systemctl disable "$unit" 2>/dev/null || true
  fi
done

if [[ -f "$SNAP" ]]; then
  log "restoring unit enablement from $SNAP"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^# ]] && continue
    [[ "$line" == *=* ]] || continue
    unit="${line%%=*}"
    state="${line#*=}"
    case "$state" in
      enabled)
        systemctl enable "$unit" 2>/dev/null || warn "could not enable $unit"
        systemctl start "$unit" 2>/dev/null || warn "could not start $unit"
        ;;
      disabled|masked)
        systemctl disable "$unit" 2>/dev/null || true
        ;;
      *) warn "unknown state for $unit: $state" ;;
    esac
  done <"$SNAP"
else
  warn "no $SNAP — re-enable nginx/caddy/xray manually if the installer stopped them"
fi

if [[ -f /etc/systemd/resolved.conf.d/90-shahrah.conf ]]; then
  rm -f /etc/systemd/resolved.conf.d/90-shahrah.conf
  systemctl restart systemd-resolved 2>/dev/null || true
  log "removed DNSStubListener override"
fi

if [[ "$PURGE" -eq 1 ]]; then
  warn "purging $CONF_DIR (state, keys)"
  rm -rf "$CONF_DIR" /opt/shahrah
fi

log "rollback finished (config kept unless --purge-config)"
