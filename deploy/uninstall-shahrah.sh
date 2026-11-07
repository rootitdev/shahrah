#!/usr/bin/env bash
# Stop/disable Shahrah units, remove unit files, scoped UFW deletes; optional --purge for data.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHAHRAH_SRC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SHAHRAH_APP_DIR="${SHAHRAH_APP_DIR:-/opt/shahrah}"
# shellcheck source=lib/shahrah-cli.sh
source "$SCRIPT_DIR/lib/shahrah-cli.sh"

MANIFEST="/var/lib/shahrah/install-manifest.json"
PLAN_FILE=""
DRY_RUN=0
PURGE=0
YES=0
BACKUP=""
STOP_ONLY=0

usage() {
  cat <<'EOF'
Usage: uninstall-shahrah.sh [options]

Default (no --purge): stop/disable managed units, remove unit files, scoped ufw deletes;
                     keep /etc/shahrah state and credentials.

  --dry-run        print full plan JSON only (read-only; nothing removed)
  --purge          also remove owned data trees and provenance-matched binaries
  --backup DIR     before --purge, tar etc/shahrah + var/lib/shahrah (required to succeed)
  --yes            skip confirmation (required with --purge)
  --stop-only      only stop units (no unit-file removal, no ufw)

Never: ufw disable/reset, apt remove shared packages, delete binaries without provenance.
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
    --stop-only) STOP_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "run as root"

PLAN_FILE="$(mktemp /tmp/shahrah-uninstall-plan.XXXXXX.json)"
trap 'rm -f "$PLAN_FILE"' EXIT

plan_args=(uninstall-plan --json)
[[ "$PURGE" -eq 1 ]] && plan_args+=(--purge)

if [[ "$DRY_RUN" -eq 1 ]]; then
  log "=== پیش‌نمایش حذف (فقط خواندن — چیزی پاک نمی‌شود) ==="
else
  log "=== Shahrah uninstall plan (precomputed) ==="
fi

if ! shahrah_cli_or_die "${plan_args[@]}" >"$PLAN_FILE"; then
  die "failed to build uninstall plan"
fi

python3 - "$PLAN_FILE" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
for key in ("units", "unit_files", "ufw_delete", "paths", "binaries"):
    v = p.get(key) or []
    if v:
        print(f"{key}:", ", ".join(str(x) for x in v))
print(p.get("note", ""))
PY

[[ "$DRY_RUN" -eq 1 ]] && { log "dry-run complete — no changes made"; exit 0; }

[[ "$PURGE" -eq 1 ]] || true
if [[ "$PURGE" -eq 1 ]]; then
  [[ "$YES" -eq 1 ]] || {
    read -r -p "Type shahrah-purge to confirm data removal: " ans
    [[ "$ans" == shahrah-purge ]] || die "aborted"
  }
  if [[ -n "$BACKUP" ]]; then
    install -d -m 0700 "$BACKUP"
    bn="shahrah-backup-$(date +%Y%m%d%H%M%S).tar.gz"
    if ! tar -czf "${BACKUP%/}/$bn" -C / etc/shahrah var/lib/shahrah; then
      die "backup failed — purge aborted (fail-closed)"
    fi
    log "backup: ${BACKUP%/}/$bn"
  fi
fi

stop_unit() {
  local u="$1"
  systemctl disable --now "$u" 2>/dev/null || true
}

while read -r unit; do
  [[ -n "$unit" ]] || continue
  if [[ "$unit" == *@ ]]; then
    systemctl list-units --all "${unit}*" --no-legend 2>/dev/null \
      | awk '{print $1}' | while read -r inst; do stop_unit "$inst"; done
  fi
  stop_unit "$unit"
done < <(python3 -c "import json;[print(u) for u in json.load(open('$PLAN_FILE'))['units']]")

for f in /etc/systemd/system/shahrah-waterwall@*.service \
         /etc/systemd/system/shahrah-waterwall-exit@*.service; do
  [[ -e "$f" ]] || continue
  inst="$(basename "$f" .service)"
  stop_unit "$inst"
  rm -f "$f"
  log "removed unit file $f"
done

[[ "$STOP_ONLY" -eq 1 ]] && { log "stop-only complete"; exit 0; }

while read -r f; do
  [[ -n "$f" ]] || continue
  [[ -f "$f" ]] || continue
  rm -f "$f"
  log "removed unit file $f"
done < <(python3 -c "import json;[print(u) for u in json.load(open('$PLAN_FILE')).get('unit_files',[])]")

systemctl daemon-reload

if command -v ufw >/dev/null; then
  while read -r cmd; do
    [[ -n "$cmd" ]] || continue
    # shellcheck disable=SC2086
    $cmd >/dev/null 2>&1 || true
    log "ufw: $cmd"
  done < <(python3 -c "import json;[print(c) for c in json.load(open('$PLAN_FILE')).get('ufw_delete',[])]")
fi

if [[ "$PURGE" -eq 1 ]]; then
  while read -r path; do
    [[ -n "$path" ]] || continue
    [[ -e "$path" ]] || continue
    if [[ -L "$path" ]]; then
      die "refusing to remove symlink without review: $path"
    fi
    case "$path" in
      /etc/shahrah|/opt/shahrah|/var/lib/shahrah|/usr/local/bin/shahrah) ;;
      /etc/sysctl.d/99-shahrah.conf|/etc/systemd/resolved.conf.d/90-shahrah.conf) ;;
      *) die "purge path not in hard allowlist: $path" ;;
    esac
    if [[ -d "$path" ]]; then rm -rf --one-file-system "$path"; else rm -f "$path"; fi
    log "removed $path"
  done < <(python3 -c "import json;[print(p) for p in json.load(open('$PLAN_FILE')).get('paths',[])]")

  while read -r bin; do
    [[ -n "$bin" ]] || continue
    [[ -f "$bin" ]] || continue
    case "$bin" in
      /usr/local/bin/xray|/usr/local/bin/waterwall) rm -f "$bin"; log "removed provenance binary $bin" ;;
      *) die "unexpected binary in plan: $bin" ;;
    esac
  done < <(python3 -c "import json;[print(b) for b in json.load(open('$PLAN_FILE')).get('binaries',[])]")
fi

log "uninstall complete (SSH and global firewall left enabled)"
