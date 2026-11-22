#!/usr/bin/env bash
# Limited UFW for Germany exit — preserves SSH, blocks public stats API, does not flush unrelated rules.
#
# Usage:
#   sudo SSH_PORT=22 ./deploy/beta/firewall-germany-beta.sh
# Rollback window (default 180s): open a SECOND ssh session before cancelling rollback.
set -euo pipefail

SSH_PORT="${SSH_PORT:-22}"
ROLLBACK_SEC="${ROLLBACK_SEC:-180}"
SNAP="/var/lib/shahrah/ufw-beta.snapshot"

[[ "$(id -u)" -eq 0 ]] || { echo "run as root" >&2; exit 1; }
command -v ufw >/dev/null || { echo "ufw not installed" >&2; exit 1; }

mkdir -p /var/lib/shahrah
ufw status numbered >"$SNAP" 2>/dev/null || true
ufw --force disable 2>/dev/null || true

ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}/tcp" comment 'shahrah-beta-ssh'
ufw allow 443/tcp comment 'shahrah-reality'
# WaterWall reverse: exit dials out; tunnel 8443 is inbound on Iran not Germany
ufw limit "${SSH_PORT}/tcp"
ufw --force enable

echo "UFW enabled. Rollback in ${ROLLBACK_SEC}s unless: touch /var/lib/shahrah/ufw-beta-keep"
(
  sleep "$ROLLBACK_SEC"
  if [[ ! -f /var/lib/shahrah/ufw-beta-keep ]]; then
    ufw --force disable
    echo "UFW auto-rollback (disabled). Snapshot was $SNAP"
  fi
) &
echo "PID $! — verify SSH from a second session, then: touch /var/lib/shahrah/ufw-beta-keep"
