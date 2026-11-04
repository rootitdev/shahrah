#!/usr/bin/env bash
# Full lab run (root): topology -> data planes -> matrix + brain scenario -> teardown.
#   sudo lab/run.sh            # everything, writes lab/RESULTS.md and lab/results.json
#   sudo lab/run.sh brain      # only the failover scenario
#   KEEP=1 sudo lab/run.sh     # leave the lab up for manual poking
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ "$(id -u)" -eq 0 ]] || { echo "run as root" >&2; exit 1; }
for t in ip iptables tc nft openssl curl python3; do command -v "$t" >/dev/null || { echo "missing $t" >&2; exit 1; }; done
teardown() { "$HERE/planes.sh" down || true; "$HERE/topo.sh" down || true; }
[[ -n "${KEEP:-}" ]] || trap teardown EXIT
"$HERE/topo.sh" up
"$HERE/planes.sh" up
# Go (Xray) and Python trust the lab CA for the cdn.lab edge through SSL_CERT_FILE
ip netns exec client env SSL_CERT_FILE=/run/shahrah-lab/ca.crt python3 "$HERE/measure.py" "$@"
