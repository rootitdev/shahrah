#!/usr/bin/env bash
# Stream another exit node's access.log for sni-watch ACCESS_LOGS (NL + GE).
set -euo pipefail
GE_HOST="${GE_LOG_HOST:-203.0.113.12}"
GE_USER="${GE_LOG_USER:-root}"
GE_LOG="${GE_ACCESS_LOG:-/var/lib/pg-node/logs/access.log}"
KEY="${GE_LOG_SSH_KEY:-/root/.ssh/shahrah_ge_log}"
OUT="${GE_LOG_MIRROR:-/var/lib/sni-watch/ge-access.log}"
exec ssh -o BatchMode=yes -o ConnectTimeout=20 -o ServerAliveInterval=30 \
  -o StrictHostKeyChecking=accept-new -i "$KEY" "${GE_USER}@${GE_HOST}" \
  "tail -F -n 0 ${GE_LOG}" >>"$OUT"