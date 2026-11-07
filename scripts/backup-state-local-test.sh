#!/usr/bin/env bash
# Local backup/restore drill for /etc/shahrah/state.json (no Telegram).
# Run on a node after install OR in CI with a temp state file.
set -euo pipefail

STATE="${1:-/etc/shahrah/state.json}"
DEST="${2:-/var/backups/shahrah}"
PASS_FILE="${3:-/etc/shahrah/backup.pass}"

[[ -f "$STATE" ]] || { echo "missing state: $STATE" >&2; exit 1; }
install -d -m 0700 "$DEST"
if [[ ! -s "$PASS_FILE" ]]; then
  umask 077
  openssl rand -base64 32 >"$PASS_FILE"
  chmod 0600 "$PASS_FILE"
fi
ts="$(date -u +%Y%m%dT%H%M%SZ)"
arc="$DEST/state-${ts}.json.tgz.gpg"
tar -C "$(dirname "$STATE")" -czf - "$(basename "$STATE")" \
  | gpg --batch --yes --cipher-algo AES256 --passphrase-file "$PASS_FILE" -c -o "$arc"
tmp="$(mktemp)"
gpg --batch --yes --passphrase-file "$PASS_FILE" -d -o "$tmp" "$arc"
cmp -s "$STATE" "$tmp"
rm -f "$tmp"
echo "OK encrypted backup $arc"
