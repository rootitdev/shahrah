#!/usr/bin/env bash
# Fail if _lt/ contains credential-shaped files before packaging an audit zip (item 1).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
lt="$root/_lt"
[[ -d "$lt" ]] || exit 0
shopt -s nullglob
found=0
for pat in '*creds*' '*api_key*' '_last_creds.json' 'panel_api_key.txt'; do
  for f in "$lt"/$pat "$lt"/**/$pat; do
    [[ -f "$f" ]] || continue
    echo "credential-shaped file under _lt: ${f#$root/}" >&2
    found=1
  done
done
exit "$found"
