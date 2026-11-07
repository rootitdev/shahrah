#!/usr/bin/env bash
# Remove Shahrah-owned services and files only — never SSH, unrelated panels, or global ufw reset.
set -Eeuo pipefail

CONF_DIR="/etc/shahrah"
MANIFEST="/var/lib/shahrah/install-manifest.json"
DRY_RUN=0
PURGE=0
YES=0
BACKUP=""

usage() {
  cat <<'EOF'
Usage: uninstall-shahrah.sh [--dry-run] [--purge] [--backup DIR] [--yes]

  --dry-run   show shahrah uninstall-plan only (no system changes)
  --purge     remove /etc/shahrah, /opt/shahrah, managed sysctl/resolved drop-ins
  --backup    before purge, tar state to DIR (recommended)
  --yes       skip interactive confirmation (required for --purge)

Does NOT: ufw disable/reset, apt remove shared packages, touch docker/nginx/caddy/SSH.
Pre-install sysctl/resolved changes outside our drop-ins are not magically reverted.
EOF
}

log() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --purge) PURGE=1; shift ;;
    --backup) BACKUP="${2:?--backup needs a directory}"; shift 2 ;;
    --yes) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "run as root"

if ! command -v shahrah >/dev/null; then
  die "shahrah CLI not found — install manifest cannot be validated"
fi

plan_args=(uninstall-plan)
[[ "$PURGE" -eq 1 ]] && plan_args+=(--purge)

log "=== Shahrah uninstall preview ==="
shahrah "${plan_args[@]}" --json | python3 -c '
import json,sys
p=json.load(sys.stdin)
print("units:", ", ".join(p["units"]) or "(none)")
if p.get("paths"):
    print("paths:")
    for x in p["paths"]:
        print(" ", x)
print(p.get("note",""))
'

[[ "$DRY_RUN" -eq 1 ]] && { log "dry-run complete"; exit 0; }

[[ "$PURGE" -eq 1 ]] || { log "nothing destructive without --purge (stopped here)"; exit 0; }

[[ "$YES" -eq 1 ]] || {
  read -r -p "Type shahrah-purge to confirm full removal: " ans
  [[ "$ans" == shahrah-purge ]] || die "aborted"
}

if [[ -n "$BACKUP" ]]; then
  install -d -m 0700 "$BACKUP"
  bn="shahrah-backup-$(date +%Y%m%d%H%M%S).tar.gz"
  tar -czf "${BACKUP%/}/$bn" -C / etc/shahrah var/lib/shahrah 2>/dev/null || true
  log "backup written: ${BACKUP%/}/$bn"
fi

stop_unit() {
  local u="$1"
  systemctl disable --now "$u" 2>/dev/null || true
}

# Stop template instances first
if [[ -f "$MANIFEST" ]]; then
  while read -r unit; do
    [[ -n "$unit" ]] || continue
    if [[ "$unit" == *@ ]]; then
      systemctl list-units --all "${unit}*" --no-legend 2>/dev/null | awk '{print $1}' | while read -r inst; do
        stop_unit "$inst"
      done
    fi
    stop_unit "$unit"
  done < <(python3 -c "import json;print('\n'.join(json.load(open('$MANIFEST'))['units']))")
else
  for u in shahrah-xray shahrah-waterwall shahrah-hysteria2 shahrah-paqet shahrah-brain; do
    stop_unit "$u"
  done
fi

if [[ "$PURGE" -eq 1 ]]; then
  while read -r path; do
    [[ -n "$path" ]] || continue
    case "$path" in
      /etc/shahrah|/opt/shahrah|/var/lib/shahrah|/usr/local/bin/shahrah|/usr/local/bin/waterwall|/usr/local/bin/xray) ;;
      /etc/sysctl.d/99-shahrah.conf|/etc/systemd/resolved.conf.d/90-shahrah.conf) ;;
      *)
        die "refusing to remove path outside allowlist: $path"
        ;;
    esac
    [[ -e "$path" ]] || continue
    if [[ -d "$path" ]]; then rm -rf --one-file-system "$path"; else rm -f "$path"; fi
    log "removed $path"
  done < <(shahrah uninstall-plan --purge --json | python3 -c "import json,sys;[print(p) for p in json.load(sys.stdin)['paths']]")
fi

log "uninstall finished (ufw rules may remain; delete manually if needed)"

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  :
fi
