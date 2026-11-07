#!/usr/bin/env bash
# Encrypted backup of Shahrah beta state + service metadata (no Telegram). Key stays on host.
set -euo pipefail

CONF="${CONF_DIR:-/etc/shahrah}"
DEST="${BACKUP_DEST:-/var/backups/shahrah}"
PASS_FILE="${BACKUP_PASS_FILE:-/etc/shahrah/backup.pass}"
RETAIN="${BACKUP_RETAIN:-14}"

[[ -d "$CONF" ]] || { echo "missing $CONF" >&2; exit 1; }
install -d -m 0700 "$DEST"
umask 077
[[ -s "$PASS_FILE" ]] || openssl rand -base64 32 >"$PASS_FILE"
chmod 0600 "$PASS_FILE"

ts="$(date -u +%Y%m%dT%H%M%SZ)"
bundle="$DEST/shahrah-bundle-${ts}"
mkdir -p "$bundle"
cp -a "$CONF/state.json" "$bundle/" 2>/dev/null || true
cp -a "$CONF/xray.json" "$bundle/" 2>/dev/null || true
cp -a "$CONF/backhaul.key" "$bundle/" 2>/dev/null || true
cp -a "$CONF/brain.json" "$bundle/" 2>/dev/null || true
cp -a "$CONF/brain.env" "$bundle/" 2>/dev/null || true
cp -a "$CONF/waterwall" "$bundle/" 2>/dev/null || true
systemctl show shahrah-xray shahrah-waterwall shahrah-brain 2>/dev/null \
  >"$bundle/systemd-units.txt" || true
ls -la "$CONF" >"$bundle/ls-conf.txt"
( cd "$bundle" && tar -czf - . ) \
  | gpg --batch --yes --cipher-algo AES256 --passphrase-file "$PASS_FILE" -c \
  -o "${bundle}.tar.gz.gpg"
rm -rf "$bundle"
chmod 0600 "${bundle}.tar.gz.gpg"

find "$DEST" -name 'shahrah-bundle-*.tar.gz.gpg' -mtime +"$RETAIN" -delete 2>/dev/null || true
echo "OK ${bundle}.tar.gz.gpg"
