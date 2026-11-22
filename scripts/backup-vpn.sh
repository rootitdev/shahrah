#!/usr/bin/env bash
# Legacy name (vpn-infra-kit) → Shahrah stack backup.
exec "$(cd "$(dirname "$0")" && pwd)/backup-stack.sh" "$@"