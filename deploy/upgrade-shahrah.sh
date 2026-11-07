#!/usr/bin/env bash
# Upgrade from a git checkout (default /opt/shahrah). Preserves /etc/shahrah credentials.
set -Eeuo pipefail

APP_DIR="${APP_DIR:-/opt/shahrah}"
CONF_DIR="/etc/shahrah"
REF="${SHAHRAH_REF:-main}"
VENV="${SHAHRAH_VENV:-$APP_DIR/venv}"

usage() {
  cat <<EOF
Usage: upgrade-shahrah.sh [--ref REF] [--app-dir DIR]

  Fast-forward only to origin/REF (no branch overwrite). Blocks on any git dirty/untracked
  tree under APP_DIR. Reinstalls the Python package into $VENV then re-runs install.sh
  using hosts from existing state.json (no accidental host/target change).

  On trees older than this script (e.g. 672e813), fetch first:
    cd $APP_DIR && git fetch origin && git checkout <branch>
  then run this script from the updated tree.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref) REF="${2:?}"; shift 2 ;;
    --app-dir) APP_DIR="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || { echo "run as root" >&2; exit 2; }
[[ -d "$APP_DIR/.git" ]] || { echo "not a git checkout: $APP_DIR" >&2; exit 2; }

if [[ -n "$(git -C "$APP_DIR" status --porcelain)" ]]; then
  echo "working tree not clean (tracked or untracked) — commit/stash before upgrade" >&2
  exit 2
fi

BRANCH="$(git -C "$APP_DIR" branch --show-current || true)"
git -C "$APP_DIR" fetch origin "$REF"
if [[ -z "$BRANCH" ]]; then
  git -C "$APP_DIR" checkout -B "$REF" "origin/$REF"
else
  git -C "$APP_DIR" merge --ff-only "origin/$REF" \
    || { echo "fast-forward to origin/$REF failed — resolve on a branch, do not force" >&2; exit 2; }
fi

PY=python3
"$PY" -c 'import sys; exit(0 if sys.version_info>=(3,11) else 1)' || PY=python3.11
"$PY" -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade "$APP_DIR"
ln -sf "$VENV/bin/shahrah" /usr/local/bin/shahrah

if [[ ! -f "$CONF_DIR/state.json" ]]; then
  echo "no $CONF_DIR/state.json — run deploy/install.sh --host ... --target ..." >&2
  exit 1
fi

host="$(python3 -c "import json;print(json.load(open('$CONF_DIR/state.json'))['public_host'])")"
target="$(python3 -c "import json;print(json.load(open('$CONF_DIR/state.json'))['target_host'])")"
exec "$APP_DIR/deploy/install.sh" --host "$host" --target "$target"
