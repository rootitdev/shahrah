#!/usr/bin/env bash
# Install static Xray access-log launcher for PasarGuard Node + shared log mounts.
set -euo pipefail

WRAP_DIR=/var/lib/pg-node/xray-wrap
SNI_WRAP_SRC="$(cd "$(dirname "$0")/../panels/sni-watch" && pwd)"
REAL=/var/lib/pg-node/xray-core/xray.real
BIN=$WRAP_DIR/xray-access-launcher
GO_SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
# Shared with host via /var/lib/pg-node bind-mount (always present).
ACCESS=/var/lib/pg-node/logs/access.log
ERROR=/var/lib/pg-node/logs/error.log
# Compat path for sni-watch / older docs (also bind-mounted by compose).
ACCESS_COMPAT=/var/lib/shahrah/access.log

[[ "$(id -u)" -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -f "$REAL" ]] || { echo "missing $REAL — install pg-node first" >&2; exit 1; }

install -d -m 755 "$WRAP_DIR" /var/lib/pg-node/logs /var/lib/pg-node/tmp /var/lib/shahrah /var/log/xray
touch /var/log/xray/sni-access.log
chmod 644 /var/log/xray/sni-access.log
if [[ -d "$SNI_WRAP_SRC" ]]; then
  for f in xray-stdin-wrap.sh xray-stdin-wrap.py ensure_xray_wrap.sh; do
 	if [[ -f "$SNI_WRAP_SRC/$f" ]]; then
      install -m 755 "$SNI_WRAP_SRC/$f" "$WRAP_DIR/$f"
 	fi
  done
fi
touch "$ACCESS" "$ERROR"
chmod 644 "$ACCESS" "$ERROR"
# Keep legacy path as a hard link / symlink into the shared mount file.
if [[ -f "$ACCESS_COMPAT" && ! -L "$ACCESS_COMPAT" ]]; then
  # Preserve any historical host-only file, then point tools at the live log.
  mv -f "$ACCESS_COMPAT" "${ACCESS_COMPAT}.host-stale.$(date +%s)" || true
fi
ln -sfn "$ACCESS" "$ACCESS_COMPAT"

need_build=1
if [[ -x "$BIN" && "${FORCE_REBUILD:-0}" != "1" ]]; then
  need_build=0
fi

if [[ "$need_build" == "1" ]]; then
  echo "building static launcher (golang docker image)…"
  cp -f "$GO_SRC_DIR/xray-access-launcher.go" /tmp/xray-access-launcher.go
  docker run --rm -v /tmp:/src -w /src golang:1.22-alpine \
    go build -ldflags='-s -w' -o /src/xray-access-launcher /src/xray-access-launcher.go
  install -m 755 /tmp/xray-access-launcher "$BIN"
fi

rm -f /var/lib/pg-node/xray-core/xray
install -m 755 "$BIN" /var/lib/pg-node/xray-core/xray

# Normalize /opt/pg-node/.env (no spaces around =; docker env_file is picky).
if [[ -f /opt/pg-node/.env ]]; then
  tmp=$(mktemp)
  # drop old XRAY_* lines we manage
  grep -vE '^(XRAY_EXECUTABLE_PATH|XRAY_REAL|XRAY_ACCESS_LOG|XRAY_ERROR_LOG)=' /opt/pg-node/.env \
    | sed -E 's/^([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*/\1=/' \
    | sed -E 's/^([A-Za-z_][A-Za-z0-9_]*)="(.*)"$/\1=\2/' \
    >"$tmp" || true
  {
    cat "$tmp"
    echo "XRAY_EXECUTABLE_PATH=/var/lib/pg-node/xray-core/xray"
    echo "XRAY_REAL=$REAL"
    echo "XRAY_ACCESS_LOG=$ACCESS"
    echo "XRAY_ERROR_LOG=$ERROR"
  } | awk 'NF && !seen[$0]++' >/opt/pg-node/.env
  rm -f "$tmp"
  chmod 600 /opt/pg-node/.env
fi

# Ensure compose binds log dirs visible to host tools.
if [[ -f /opt/pg-node/docker-compose.yml ]]; then
  cp -f "$GO_SRC_DIR/docker-compose.yml" /opt/pg-node/docker-compose.yml
fi

printf '%s' '{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}]}' \
  | timeout 3 env XRAY_REAL="$REAL" XRAY_ACCESS_LOG="$ACCESS" XRAY_ERROR_LOG="$ERROR" \
    /var/lib/pg-node/xray-core/xray -c stdin: >/tmp/xray-access-launcher.test.log 2>&1 \
  || true
if grep -q 'Xray ' /tmp/xray-access-launcher.test.log; then
  echo "launcher self-test: ok"
else
  echo "warn: self-test banner missing — see /tmp/xray-access-launcher.test.log" >&2
  cat /tmp/xray-access-launcher.test.log >&2 || true
fi

# Recreate node so new volume mounts + env take effect.
if [[ -f /opt/pg-node/docker-compose.yml ]]; then
  (cd /opt/pg-node && docker compose up -d --force-recreate node)
else
  docker restart node
fi

# Point sni-watch at the shared log if present.
if [[ -f /etc/sni-watch/config.env ]]; then
  if grep -q '^ACCESS_LOG=' /etc/sni-watch/config.env; then
    sed -i -E "s|^ACCESS_LOG=.*|ACCESS_LOG=$ACCESS|" /etc/sni-watch/config.env
  else
    echo "ACCESS_LOG=$ACCESS" >>/etc/sni-watch/config.env
  fi
  # also clear ACCESS_LOGS override if it pointed at stale paths
  SNI_ACCESS=/var/log/xray/sni-access.log
  dual="${SNI_ACCESS},${ACCESS}"
  if grep -q '^ACCESS_LOGS=' /etc/sni-watch/config.env; then
    sed -i -E "s|^ACCESS_LOGS=.*|ACCESS_LOGS=$dual|" /etc/sni-watch/config.env
  else
    echo "ACCESS_LOGS=$dual" >>/etc/sni-watch/config.env
  fi
  systemctl restart sni-watch 2>/dev/null || true
fi

echo "installed $BIN → /var/lib/pg-node/xray-core/xray"
echo "access log: $ACCESS (compat symlink: $ACCESS_COMPAT)"
echo "reconnect node from panel now"
