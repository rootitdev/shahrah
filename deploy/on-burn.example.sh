#!/usr/bin/env bash
# Example --on-burn hook for `shahrah brain`.
# Receives burned endpoint names as arguments (no IPs/secrets).
# Replace the body with your provisioning: promote a standby host, retarget SNI, page ops, …
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <endpoint-name> [more…]" >&2
  exit 2
fi

logger -t shahrah-burn "burned endpoints: $*"
# Example only — do not enable blindly:
#   for name in "$@"; do
#     shahrah panel …   # disable host / raise priority of standby
#   done
exit 0
