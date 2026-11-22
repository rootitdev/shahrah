#!/usr/bin/env bash
# Idempotent 2GiB swapfile for small VPS (master / exit / relay).
set -euo pipefail

SIZE_GiB="${SWAP_SIZE_GiB:-2}"
SWAPFILE="${SWAPFILE:-/swapfile}"
SWAPPINESS="${SWAPPINESS:-10}"

if swapon --show 2>/dev/null | grep -q .; then
  if swapon --show | grep -qv "$SWAPFILE"; then
    echo "[swap] another swap already active ($(swapon --show | head -1))"
  else
    echo "[swap] OK already on $SWAPFILE"
  fi
else
  if [[ ! -f "$SWAPFILE" ]]; then
    fallocate -l "${SIZE_GiB}G" "$SWAPFILE" 2>/dev/null \
      || dd if=/dev/zero of="$SWAPFILE" bs=1M count="$((SIZE_GiB * 1024))" status=none
    chmod 600 "$SWAPFILE"
    mkswap "$SWAPFILE"
  fi
  swapon "$SWAPFILE"
  grep -qF "$SWAPFILE" /etc/fstab 2>/dev/null \
    || echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab
  echo "[swap] enabled ${SIZE_GiB}G at $SWAPFILE"
fi

SYSCTL=/etc/sysctl.d/99-shahrah-swap.conf
if [[ ! -f "$SYSCTL" ]] || ! grep -q "vm.swappiness=$SWAPPINESS" "$SYSCTL" 2>/dev/null; then
  install -d -m 0755 /etc/sysctl.d
  echo "vm.swappiness=$SWAPPINESS" >"$SYSCTL"
fi
sysctl -w "vm.swappiness=$SWAPPINESS" >/dev/null 2>&1 || true