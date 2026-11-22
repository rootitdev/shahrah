#!/usr/bin/env bash
# Limited UFW for Iran WaterWall relay.
#
# Usage:
#   sudo SSH_PORT=22 EXIT_PEER_IP=203.0.113.9 TUNNEL_PORT=8443 ./deploy/beta/firewall-iran-relay.sh
set -euo pipefail

SSH_PORT="${SSH_PORT:-22}"
EXIT_PEER_IP="${EXIT_PEER_IP:-}"
TUNNEL_PORT="${TUNNEL_PORT:-8443}"
ROLLBACK_SEC="${ROLLBACK_SEC:-180}"

[[ -n "$EXIT_PEER_IP" ]] || { echo "set EXIT_PEER_IP" >&2; exit 2; }
[[ "$(id -u)" -eq 0 ]] || exit 1

ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}/tcp"
ufw allow 443/tcp comment 'ww-user-facing'
ufw allow from "$EXIT_PEER_IP" to any port "$TUNNEL_PORT" proto tcp comment 'ww-from-exit'
ufw --force enable

echo "UFW enabled (Iran). Rollback: disable ufw or rebootless: ufw --force disable"
echo "Confirm SSH in ${ROLLBACK_SEC}s; then touch /var/lib/shahrah/ufw-beta-keep"
(
  sleep "$ROLLBACK_SEC"
  [[ -f /var/lib/shahrah/ufw-beta-keep ]] || ufw --force disable
) &
