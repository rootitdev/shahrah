#!/usr/bin/env bash
# Thin emergency SSH L-forward when WaterWall reverse leg is down (ops smoke tests).
# Production client traffic should use vpn-infra-kit TO-NL-SSH / TO-AMS-SSH SOCKS paths
# (see vpn-infra-kit/docs/SSH-PATH.md) — not this port-forward alone.
# Runs on IRAN: autossh -> NL, forwards localhost:127.0.0.1:10443 -> NL:127.0.0.1:443
#
# Usage (on Iran, as root):
#   export SSH_FALLBACK_PEER=185.19.33.221
#   export SSH_FALLBACK_USER=root
#   ./deploy/install-ssh-fallback.sh
#
# Optional: place pubkey auth first (recommended) — script still works with password
# if sshpass is installed (not required for key auth).
set -euo pipefail

PEER="${SSH_FALLBACK_PEER:?set SSH_FALLBACK_PEER (exit IP)}"
RUSER="${SSH_FALLBACK_USER:-root}"
LOCAL_PORT="${SSH_FALLBACK_LOCAL_PORT:-10443}"
REMOTE_PORT="${SSH_FALLBACK_REMOTE_PORT:-443}"
REMOTE_BIND="${SSH_FALLBACK_REMOTE_BIND:-127.0.0.1}"

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "run as root"
command -v autossh >/dev/null || {
  apt-get update -qq && apt-get install -y -qq autossh openssh-client
}

install -d -m 700 /root/.ssh
if [[ ! -f /root/.ssh/id_ed25519 ]]; then
  ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519 -q
  log "generated /root/.ssh/id_ed25519 — copy to ${RUSER}@${PEER}:"
  cat /root/.ssh/id_ed25519.pub
  log "run on exit: mkdir -p ~/.ssh && echo '<pubkey>' >> ~/.ssh/authorized_keys"
fi

unit=/etc/systemd/system/shahrah-ssh-fallback.service
cat >"$unit" <<EOF
[Unit]
Description=Shahrah emergency SSH port-forward Iran -> Exit (Xray)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=AUTOSSH_GATETIME=0
ExecStart=/usr/bin/autossh -M 0 -N -o BatchMode=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \\
  -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=accept-new \\
  -L 127.0.0.1:${LOCAL_PORT}:${REMOTE_BIND}:${REMOTE_PORT} ${RUSER}@${PEER}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

ssh-keyscan -H "$PEER" >>/root/.ssh/known_hosts 2>/dev/null || true
systemctl daemon-reload
systemctl enable --now shahrah-ssh-fallback
log "listening 127.0.0.1:${LOCAL_PORT} -> ${PEER}:${REMOTE_BIND}:${REMOTE_PORT}"
systemctl is-active shahrah-ssh-fallback
