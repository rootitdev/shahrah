#!/usr/bin/env bash
# Restrict PasarGuard panel port to trusted admin sources (default: Iran relay IP only).
# Public VPN 443 stays open; only trims world access to :8000.
set -euo pipefail

PANEL_PORT="${PANEL_PORT:-8000}"
ALLOW_FROM="${ALLOW_PANEL_FROM:?set ALLOW_PANEL_FROM (e.g. Iran relay CIDR or IP)}"

[[ "$(id -u)" -eq 0 ]] || { echo "root required" >&2; exit 1; }
command -v ufw >/dev/null || { echo "ufw missing" >&2; exit 1; }

while ufw status numbered | grep -q "${PANEL_PORT}/tcp"; do
  num="$(ufw status numbered | grep "${PANEL_PORT}/tcp" | head -1 | sed -n 's/^\[\s*\([0-9]*\)\].*/\1/p')"
  [[ -n "$num" ]] || break
  ufw --force delete "$num" || break
done

ufw allow from "$ALLOW_FROM" to any port "$PANEL_PORT" proto tcp comment "pasarguard-panel"
ufw reload
echo "panel ${PANEL_PORT}/tcp now only from ${ALLOW_FROM}"
