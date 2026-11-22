#!/usr/bin/env bash
# Shahrah production backup: master (+ optional Iran/exit over SSH) → tar → GPG.
# Passphrase: BACKUP_PASSPHRASE in /root/.vpn-secrets/.env or /etc/shahrah/backup.pass
set -euo pipefail

SECRETS="${BACKUP_SECRETS:-/root/.vpn-secrets/.env}"
PASS_FILE="${BACKUP_PASS_FILE:-/etc/shahrah/backup.pass}"
DEST="${BACKUP_DEST:-/var/backups/shahrah}"
RETAIN="${BACKUP_RETAIN:-14}"
IRAN_HOST="${BACKUP_IRAN_HOST:-}"
EXIT_HOST="${BACKUP_EXIT_HOST:-}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

log() { printf '[backup] %s\n' "$*" >&2; }
die() { printf '[backup] ERROR %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "run as root"

load_pass() {
  local pass=""
  if [[ -f "$SECRETS" ]]; then
    # shellcheck disable=SC1090
    set -a
    # shellcheck source=/dev/null
    source "$SECRETS"
    set +a
    pass="${BACKUP_PASSPHRASE:-}"
  fi
  if [[ -z "$pass" && -s "$PASS_FILE" ]]; then
    pass="$(tr -d '\n\r' <"$PASS_FILE")"
  fi
  if [[ -z "$pass" ]]; then
    install -d -m 0700 "$(dirname "$PASS_FILE")"
    umask 077
    openssl rand -base64 32 >"$PASS_FILE"
    chmod 0600 "$PASS_FILE"
    pass="$(tr -d '\n\r' <"$PASS_FILE")"
    log "generated new passphrase in $PASS_FILE (also set BACKUP_PASSPHRASE in secrets)"
  fi
  export BACKUP_PASSPHRASE="$pass"
}

copy_tree() {
  local src=$1 dst=$2
  [[ -e "$src" ]] || return 0
  mkdir -p "$(dirname "$dst")"
  cp -a "$src" "$dst"
}

panel_db_snap() {
  local out=$1
  local snap=/var/lib/pasarguard/.backup-snapshot.sqlite3
  rm -f "$snap"
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx pasarguard; then
    docker exec -i pasarguard python - <<'PY' || log "WARN: panel DB online backup failed"
import os, re, sqlite3
url = os.environ.get("SQLALCHEMY_DATABASE_URL") or "sqlite+aiosqlite:///db.sqlite3"
m = re.match(r"sqlite(?:\+\w+)?:///(.+)$", url)
src_path = m.group(1) if m else "db.sqlite3"
src = sqlite3.connect(src_path if src_path.startswith("/") else "/code/" + src_path, timeout=30)
dst = sqlite3.connect("/var/lib/pasarguard/.backup-snapshot.sqlite3")
src.backup(dst)
dst.close()
src.close()
PY
  fi
  [[ -s "$snap" ]] && mv "$snap" "$out"
}

collect_local_master() {
  local root=$1
  mkdir -p "$root/master"/{etc,root,var,opt,systemd,usr-local}
  copy_tree "$SECRETS" "$root/master/root/.vpn-secrets"
  copy_tree /opt/shahrah "$root/master/opt/shahrah"
  if [[ -d /opt/pasarguard ]]; then
    mkdir -p "$root/master/opt/pasarguard"
    for f in docker-compose.yml compose.yml .env; do
      copy_tree "/opt/pasarguard/$f" "$root/master/opt/pasarguard/$f"
    done
    copy_tree /opt/pasarguard/bin "$root/master/opt/pasarguard/bin"
  fi
  for d in settle-web ig-mult-web sni-watch path-web; do
    copy_tree "/etc/$d" "$root/master/etc/$d"
    copy_tree "/usr/local/lib/$d" "$root/master/usr-local/lib/$d"
  done
  copy_tree /etc/shahrah "$root/master/etc/shahrah"
  copy_tree /var/lib/shahrah "$root/master/var/shahrah"
  copy_tree /var/lib/settle-web "$root/master/var/settle-web"
  copy_tree /etc/letsencrypt "$root/master/etc/letsencrypt"
  copy_tree /root/.vpn-secrets/path-web.env "$root/master/root/.vpn-secrets/path-web.env"
  panel_db_snap "$root/master/pasarguard.sqlite3" || echo "panel_db=missing" >"$root/master/PANEL_DB_MISSING.txt"
  shopt -s nullglob
  for u in /etc/systemd/system/shahrah*.service \
           /etc/systemd/system/shahrah*.timer \
           /etc/systemd/system/settle-web.service \
           /etc/systemd/system/ig-mult-web.service \
           /etc/systemd/system/path-web.service \
           /etc/systemd/system/sni-watch*.service \
           /etc/systemd/system/pasarguard.service; do
    [[ -e "$u" ]] && cp -a "$u" "$root/master/systemd/"
  done
  shopt -u nullglob
  if [[ -x /opt/shahrah/venv/bin/shahrah ]]; then
  /opt/shahrah/venv/bin/shahrah panel snapshot --out "$root/master/var/shahrah/panel-snapshots" \
    2>/dev/null || true
  fi
}

collect_local_node() {
  local root=$1 role=$2
  mkdir -p "$root/$role"
  copy_tree /etc/shahrah "$root/$role/etc/shahrah"
  copy_tree /etc/shahrah/waterwall "$root/$role/etc/shahrah/waterwall"
  copy_tree /etc/sni-watch "$root/$role/etc/sni-watch"
  copy_tree /etc/path-web "$root/$role/etc/path-web"
  copy_tree /var/log/shahrah "$root/$role/var/log/shahrah"
  shopt -s nullglob
  for u in /etc/systemd/system/shahrah*.service \
           /etc/systemd/system/shahrah*.timer \
           /etc/systemd/system/sni-watch*.service; do
    [[ -e "$u" ]] && mkdir -p "$root/$role/systemd" && cp -a "$u" "$root/$role/systemd/"
  done
  shopt -u nullglob
}

collect_ssh() {
  local host=$1 out="$2/archive.tgz"
  [[ -n "$host" ]] || return 0
  log "collect via ssh: $host"
  mkdir -p "$(dirname "$out")"
  if ! ssh -o BatchMode=yes -o ConnectTimeout=25 "$host" bash -s <<'REMOTE' >"$out"
set -euo pipefail
paths=()
add() { [[ -e "$1" ]] && paths+=("$1"); }
add /etc/shahrah
add /etc/sni-watch
add /etc/path-web
add /var/log/shahrah
add /opt/shahrah
[[ ${#paths[@]} -eq 0 ]] && exit 1
tar -czf - -C / "${paths[@]#/}"
REMOTE
  then
    log "WARN: ssh collect failed for $host"
    rm -f "$out"
    return 1
  fi
}

main() {
  load_pass
  install -d -m 0700 "$DEST"
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  STAGE="$TMP/stack-$STAMP"
  mkdir -p "$STAGE/meta"

  if [[ -d /opt/pasarguard ]] || docker ps 2>/dev/null | grep -q pasarguard; then
    collect_local_master "$STAGE"
    echo "role=master" >>"$STAGE/meta/README.txt"
  else
    if systemctl is-active shahrah-waterwall &>/dev/null; then
      collect_local_node "$STAGE" iran
      echo "role=iran" >>"$STAGE/meta/README.txt"
    else
      collect_local_node "$STAGE" exit
      echo "role=exit" >>"$STAGE/meta/README.txt"
    fi
  fi

  [[ -n "$IRAN_HOST" ]] && collect_ssh "$IRAN_HOST" "$STAGE/remote-iran" || true
  [[ -n "$EXIT_HOST" ]] && collect_ssh "$EXIT_HOST" "$STAGE/remote-exit" || true

  {
    echo "stamp=$STAMP"
    echo "host=$(hostname -f 2>/dev/null || hostname)"
    echo "created_utc=$(date -u -Iseconds)"
    echo "iran_host=$IRAN_HOST"
    echo "exit_host=$EXIT_HOST"
  } >>"$STAGE/meta/README.txt"

  cat >"$STAGE/meta/RESTORE.txt" <<'EOF'
1) gpg -d shahrah-stack-*.tar.gz.gpg | tar -xzf -
2) Master: restore /opt/pasarguard, panel sqlite, /root/.vpn-secrets, panel /etc/*
3) Nodes: restore /etc/shahrah, systemctl daemon-reload
4) See docs/BACKUP.md and scripts/restore-shahrah-drill.sh
EOF

  out="$DEST/shahrah-stack-${STAMP}.tar.gz"
  tar -czf "$out" -C "$TMP" "stack-$STAMP"
  gpg --batch --yes --cipher-algo AES256 --passphrase "$BACKUP_PASSPHRASE" -c -o "${out}.gpg" "$out"
  rm -f "$out"
  chmod 0600 "${out}.gpg"
  find "$DEST" -name 'shahrah-stack-*.tar.gz.gpg' -mtime +"$RETAIN" -delete 2>/dev/null || true
  log "OK ${out}.gpg"
}

main "$@"