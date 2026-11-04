#!/usr/bin/env bash
# Switch the censor namespace to a profile. Usage: censor.sh <profile>
# Profiles: open sni-dpi udp-block udp-throttle allowlist-ip icmp-only dns-poison
#           lossy-mobile shutdown
# Only traffic entering from the client side (c1) is censored; see README "limits".
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN=/run/shahrah-lab
P="${1:?profile}"
C="ip netns exec censor"
mkdir -p "$RUN"

reset() {
  $C iptables -F FORWARD; $C iptables -t mangle -F; $C iptables -t nat -F
  $C iptables -P FORWARD ACCEPT
  # strict conntrack: a mid-stream packet (paqet raw TCP, a flow from the previous profile) is
  # not "ESTABLISHED" just because both directions were seen.
  $C sysctl -qw net.netfilter.nf_conntrack_tcp_loose=0 2>/dev/null || true
  for d in c1 i1; do $C tc qdisc del dev "$d" root 2>/dev/null || true; done
  if [[ -f "$RUN/dpi.pid" ]]; then kill "$(cat "$RUN/dpi.pid")" 2>/dev/null || true; rm -f "$RUN/dpi.pid"; fi
  $C conntrack -F >/dev/null 2>&1 || true
  echo truth > "$RUN/dns_mode"
}

fw() { $C iptables -A FORWARD -i c1 "$@"; }
established() { $C iptables -A FORWARD -i c1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; }

reset
case "$P" in
  open) ;;
  sni-dpi)
    # REJECT what the DPI marked (mark 1 = this packet, connmark 1 = whole flow)
    fw -p tcp -m connmark --mark 1 -j REJECT --reject-with tcp-reset
    fw -p tcp -m mark --mark 1 -j CONNMARK --save-mark
    fw -p tcp -m mark --mark 1 -j REJECT --reject-with tcp-reset
    fw -p tcp --dport 443 -j NFQUEUE --queue-num 7 --queue-bypass
    $C python3 "$HERE/dpi.py" --queue 7 --allow "$HERE/allowlist.txt" >"$RUN/dpi.log" 2>&1 &
    echo $! > "$RUN/dpi.pid"
    sleep 0.5 ;;
  udp-block) fw -p udp ! --dport 53 -j DROP ;;
  udp-throttle)
    # QUIC survives a handshake but sustained flows are starved (observed Iranian behaviour)
    fw -p udp ! --dport 53 -m hashlimit --hashlimit-name udpthr --hashlimit-mode srcip \
      --hashlimit-above 60/sec --hashlimit-burst 30 -j DROP ;;
  allowlist-ip)
    established
    fw -d 10.0.2.2 -j ACCEPT
    fw -d 23.5.100.2 -j ACCEPT
    fw -j DROP ;;
  icmp-only) established; fw -p icmp -j ACCEPT; fw -j DROP ;;
  dns-poison) echo poison > "$RUN/dns_mode" ;;
  lossy-mobile)
    for d in c1 i1; do $C tc qdisc add dev "$d" root netem delay 75ms 15ms loss 2%; done ;;
    # applied on both directions: ~150 ms RTT, ~30 ms jitter, ~4% round-trip loss
  shutdown) fw -j DROP ;;
  *) echo "unknown profile: $P" >&2; exit 2 ;;
esac
echo "$P" > "$RUN/profile"
echo "censor profile: $P"
