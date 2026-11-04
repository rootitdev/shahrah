#!/usr/bin/env bash
# Switch a censor to a profile.  Usage: censor.sh [--leg client|intl] <profile>
#   client leg (default): the access ISP, in the `censor` namespace, on traffic from the client.
#   intl leg: the international gateway, in the `inet` namespace, on everything leaving Iran
#             (the client's foreign traffic *and* the iran relay's backhaul to the exit).
# Profiles: open sni-dpi sni-dpi-strict udp-block udp-throttle allowlist-ip icmp-only
#           dns-poison(client only) lossy-mobile shutdown.   `censor.sh reset` clears both legs.
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN=/run/shahrah-lab
LEG=client
if [[ "${1:-}" == --leg ]]; then LEG="$2"; shift 2; fi
P="${1:?profile}"
mkdir -p "$RUN"

leg_vars() {
  case "$1" in
    client) NS=censor; IN=c1; QUEUE=7; NETEM=(censor:c1 censor:i1)
            ALLOW_IPS=(10.0.2.2 198.18.5.2) ;;  # domestic relay + one allowlisted foreign site
    intl)   NS=inet; IN=n1; QUEUE=8; NETEM=(inet:n1 iran:n0)
            ALLOW_IPS=(198.18.5.2 198.18.6.2) ;; # allowlisted foreign site + a big CDN
    *) echo "unknown leg: $1" >&2; exit 2 ;;
  esac
  C="ip netns exec $NS"
}

reset_leg() {
  leg_vars "$1"
  $C iptables -F FORWARD; $C iptables -t mangle -F; $C iptables -t nat -F
  $C iptables -P FORWARD ACCEPT
  # strict conntrack: a mid-stream packet (paqet raw TCP, a flow from the previous profile) is
  # not "ESTABLISHED" just because both directions were seen.
  $C sysctl -qw net.netfilter.nf_conntrack_tcp_loose=0 2>/dev/null || true
  for nd in "${NETEM[@]}"; do ip netns exec "${nd%%:*}" tc qdisc del dev "${nd#*:}" root 2>/dev/null || true; done
  if [[ -f "$RUN/dpi-$1.pid" ]]; then kill "$(cat "$RUN/dpi-$1.pid")" 2>/dev/null || true; rm -f "$RUN/dpi-$1.pid"; fi
  $C conntrack -F >/dev/null 2>&1 || true
  rm -f "$RUN/profile-$1"
}

if [[ "$P" == reset ]]; then reset_leg client; reset_leg intl; echo truth > "$RUN/dns_mode"; exit 0; fi

fw() { $C iptables -A FORWARD -i "$IN" "$@"; }
established() { $C iptables -A FORWARD -i "$IN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; }

dpi() { # extra dpi.py args...
  # mark 1 = this packet judged bad, connmark 1 = the whole flow: TCP gets a RST, UDP is dropped
  fw -p tcp -m connmark --mark 1 -j REJECT --reject-with tcp-reset
  fw -p udp -m connmark --mark 1 -j DROP
  fw -m mark --mark 1 -j CONNMARK --save-mark
  fw -p tcp -m mark --mark 1 -j REJECT --reject-with tcp-reset
  fw -p udp -m mark --mark 1 -j DROP
  # every TCP port (REALITY/XHTTP on :80 is still TLS) and the first packet of each UDP flow
  # (a QUIC Initial carries the ClientHello; later packets are opaque anyway)
  fw -p tcp -j NFQUEUE --queue-num "$QUEUE" --queue-bypass
  fw -p udp ! --dport 53 -m conntrack --ctstate NEW -j NFQUEUE --queue-num "$QUEUE" --queue-bypass
  $C python3 "$HERE/dpi.py" --queue "$QUEUE" --allow "$HERE/allowlist.txt" "$@" \
    >"$RUN/dpi-$LEG.log" 2>&1 &
  echo $! > "$RUN/dpi-$LEG.pid"
  sleep 0.5
}

reset_leg "$LEG"
[[ "$LEG" == client ]] && echo truth > "$RUN/dns_mode"
case "$P" in
  open) ;;
  sni-dpi) dpi ;;
  sni-dpi-strict) dpi --strict-udp ;;  # also drop UDP flows that are not readable QUIC
  udp-block) fw -p udp ! --dport 53 -j DROP ;;
  udp-throttle)
    # QUIC survives a handshake but sustained flows are starved (observed Iranian behaviour)
    fw -p udp ! --dport 53 -m hashlimit --hashlimit-name "udpthr$LEG" --hashlimit-mode srcip \
      --hashlimit-above 60/sec --hashlimit-burst 30 -j DROP ;;
  allowlist-ip)
    established
    for ip in "${ALLOW_IPS[@]}"; do fw -d "$ip" -j ACCEPT; done
    fw -j DROP
    if [[ "$LEG" == intl ]]; then
      # the gateway filters by foreign IP in both directions, so a tunnel the exit opens
      # towards Iran (WaterWall reverse mode) is not let in just because it is "a reply"
      for ip in "${ALLOW_IPS[@]}"; do $C iptables -I FORWARD 1 -o n1 -s "$ip" -j ACCEPT; done
      $C iptables -A FORWARD -o n1 -j DROP
    fi ;;
  icmp-only) established; fw -p icmp -j ACCEPT; fw -j DROP ;;
  dns-poison)
    [[ "$LEG" == client ]] || { echo "dns-poison is a client-leg profile" >&2; exit 2; }
    echo poison > "$RUN/dns_mode" ;;
  lossy-mobile)
    # both directions: ~150 ms RTT, ~30 ms jitter, ~4% round-trip loss
    for nd in "${NETEM[@]}"; do
      ip netns exec "${nd%%:*}" tc qdisc add dev "${nd#*:}" root netem delay 75ms 15ms loss 2%
    done ;;
  shutdown) fw -j DROP ;;
  *) echo "unknown profile: $P" >&2; exit 2 ;;
esac
echo "$P" > "$RUN/profile-$LEG"
echo "censor $LEG: $P"
