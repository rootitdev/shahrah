#!/usr/bin/env bash
# Upgrade in-place from a git checkout (default /opt/shahrah). Preserves /etc/shahrah credentials.
set -Eeuo pipefail

APP_DIR="${APP_DIR:-/opt/shahrah}"
CONF_DIR="/etc/shahrah"
REF="${SHAHRAH_REF:-main}"

usage() {
  cat <<EOF
Usage: upgrade-shahrah.sh [--ref REF] [--app-dir DIR] [--host HOST] [--target DOMAIN] [--multi-port]

  Upgrades Python package from git and re-runs idempotent install.sh for the node role.
  Does not pass --host/--target unless you set them (avoids accidental reconfigure).

  Local changes in APP_DIR block upgrade unless SHAHRAH_FORCE=1.
EOF
}

EXPLICIT_INSTALL_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref) REF="${2:?}"; shift 2 ;;
    --app-dir) APP_DIR="${2:?}"; shift 2 ;;
    --host) EXPLICIT_INSTALL_ARGS+=(--host "${2:?}"); shift 2 ;;
    --target) EXPLICIT_INSTALL_ARGS+=(--target "${2:?}"); shift 2 ;;
    --multi-port) EXPLICIT_INSTALL_ARGS+=(--multi-port); shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || { echo "run as root" >&2; exit 2; }
[[ -d "$APP_DIR/.git" ]] || { echo "not a git checkout: $APP_DIR" >&2; exit 2; }

if [[ -z "${SHAHRAH_FORCE:-}" ]] && ! git -C "$APP_DIR" diff --quiet HEAD 2>/dev/null; then
  echo "local changes in $APP_DIR — commit/stash or set SHAHRAH_FORCE=1" >&2
  exit 2
fi

git -C "$APP_DIR" fetch origin "$REF"
git -C "$APP_DIR" switch -C "shahrah-upgrade-$REF" "origin/$REF" 2>/dev/null \
  || git -C "$APP_DIR" checkout "$REF"

PY=python3
"$PY" -c 'import sys; exit(0 if sys.version_info>=(3,11) else 1)' || PY=python3.11
"$PY" -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --quiet --upgrade "$APP_DIR"
ln -sf "$APP_DIR/venv/bin/shahrah" /usr/local/bin/shahrah

if [[ -f "$CONF_DIR/state.json" ]]; then
  host="$(python3 -c "import json;print(json.load(open('$CONF_DIR/state.json'))['public_host'])")"
  target="$(python3 -c "import json;print(json.load(open('$CONF_DIR/state.json'))['target_host'])")"
  exec "$APP_DIR/deploy/install.sh" --host "$host" --target "$target" "${EXPLICIT_INSTALL_ARGS[@]}"
fi

echo "no $CONF_DIR/state.json — run deploy/install.sh --host ... manually"
exit 1
