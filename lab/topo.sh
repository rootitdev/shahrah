#!/usr/bin/env bash
# Censorship lab topology (root, network namespaces). Usage: topo.sh up|down
#
#   client(10.0.1.2) -c- censor -i- iran(10.0.2.2) -n- inet -+- exit(10.0.4.2)
#                        10.0.1.1/10.0.2.1    10.0.3.1/10.0.3.2 +- cover(198.18.5.2)
#
# All addresses are private lab ranges; nothing here touches the host's real interfaces.
set -Eeuo pipefail
NS=(client censor iran inet exit cover)
# shellcheck disable=SC2034
LAB_DNS=10.0.1.1

link() { # nsA ifA addrA nsB ifB addrB
  ip link add "$2" netns "$1" type veth peer name "$5" netns "$4"
  ip -n "$1" addr add "$3" dev "$2"; ip -n "$4" addr add "$6" dev "$5"
  ip -n "$1" link set "$2" up; ip -n "$4" link set "$5" up
}

hosts() { # per-namespace /etc/hosts and resolv.conf (ip netns exec bind-mounts these)
  mkdir -p "/etc/netns/$1"
  printf '127.0.0.1 localhost\n198.18.5.2 cover.lab\n10.0.4.2 exit.lab\n10.0.2.2 iran.lab\n' \
    > "/etc/netns/$1/hosts"
  if [[ "$1" == client ]]; then
    # the client uses the censor's resolver, so dns-poison can lie to it; hosts stays minimal
    printf '127.0.0.1 localhost\n' > "/etc/netns/$1/hosts"
    printf 'nameserver %s\noptions timeout:2 attempts:1\n' "$LAB_DNS" > "/etc/netns/$1/resolv.conf"
  else
    printf 'nameserver 127.0.0.1\n' > "/etc/netns/$1/resolv.conf"
  fi
}

up() {
  down >/dev/null 2>&1 || true
  for n in "${NS[@]}"; do ip netns add "$n"; ip -n "$n" link set lo up; hosts "$n"; done
  link client c0 10.0.1.2/24 censor c1 10.0.1.1/24
  link censor i1 10.0.2.1/24 iran i0 10.0.2.2/24
  link iran n0 10.0.3.1/24 inet n1 10.0.3.2/24
  link inet e1 10.0.4.1/24 exit e0 10.0.4.2/24
  link inet v1 198.18.5.1/24 cover v0 198.18.5.2/24
  ip -n client route add default via 10.0.1.1
  ip -n censor route add default via 10.0.2.2
  ip -n iran route add 10.0.1.0/24 via 10.0.2.1
  ip -n iran route add default via 10.0.3.2
  ip -n inet route add 10.0.1.0/24 via 10.0.3.1
  ip -n inet route add 10.0.2.0/24 via 10.0.3.1
  ip -n exit route add default via 10.0.4.1
  ip -n cover route add default via 198.18.5.1
  for n in censor iran inet; do ip netns exec "$n" sysctl -qw net.ipv4.ip_forward=1; done
  for n in "${NS[@]}"; do
    ip netns exec "$n" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 || true
  done
  # warm ARP so paqet (raw frames) and the first probes do not race neighbour discovery
  ip netns exec client ping -c1 -W1 10.0.4.2 >/dev/null 2>&1 || true
  ip netns exec exit ping -c1 -W1 10.0.1.2 >/dev/null 2>&1 || true
  echo "lab topology up"
}

down() {
  for n in "${NS[@]}"; do
    if ip netns pids "$n" >/dev/null 2>&1; then
      for p in $(ip netns pids "$n"); do kill "$p" 2>/dev/null || true; done
    fi
  done
  sleep 0.5
  for n in "${NS[@]}"; do
    for p in $(ip netns pids "$n" 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
    ip netns del "$n" 2>/dev/null || true
    rm -rf "/etc/netns/$n"
  done
  echo "lab topology down"
}

mac() { ip -n "$1" -br link show "$2" | awk '{print $3}'; }

case "${1:-}" in
  up) up ;;
  down) down ;;
  mac) mac "$2" "$3" ;;
  *) echo "usage: $0 up|down|mac NS IF" >&2; exit 2 ;;
esac
