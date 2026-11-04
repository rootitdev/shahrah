# Allowlist resilience

Goals: survive Iran's allowlist regime (net4people/bbs#630), keep Instagram/social quality
(many small, latency-sensitive flows) over bulk speed, and resist both domain (SNI) and server
(IP) filtering. Field evidence driving each piece is cited inline.

## 1. SNI ↔ DNS consistency (`sni_dns`)

bbs#668: DPI compares the TLS SNI with the destination IP; a REALITY target whose public DNS
never points near the server is flagged even when the handshake itself is perfect.

| verdict | meaning | accepted |
|---|---|---|
| `own-domain` | SNI resolves to the node IP (own domain, real cert) | always |
| `same-prefix` | SNI resolves into the node /24 (v4) or /48 (v6) | not with `--strict-dns` |
| `mismatch` | resolves elsewhere: the #668 case | no |
| `unresolved` | no A/AAAA | no |

```
shahrah sni-scout --defaults --node-ip <NODE_IP>            # run on the exit
shahrah sni-scout own.example.org --node-ip <NODE_IP> --strict-dns
```

**Own-domain mode**: point an A record of a domain you control at the node, serve a real
publicly trusted certificate for it from a local TLS 1.3 site (e.g. Caddy on loopback) and use
that site as the REALITY target. Only this mode is consistent against an exact-match check.
Note bbs#628: DPI also extracts SNI behind CDNs and young domains die fast, so rotate.

## 2. Modes and tactics (`tactics`)

The Oracle reports `normal`/`degraded`/`restricted`/`outage`. `restricted` (only
lockdown-capable paths alive) is the allowlist signature. A tactics profile per ASN and mode
lists: transport preference (`domestic-relay`, `reality-xhttp`, `cdn-xhttp`, `paqet`, ...),
port order (default 443, 80, 53), allowlisted SNIs, domestic entry hosts, and paqet on/off.
`fragment` exists only as an opt-in flag: ClientHello fragmentation no longer works in Iran
(bbs#640).

```
SHAHRAH_TACTICS_KEY=$(openssl rand -hex 32) shahrah tactics-sign profiles.json \
  --serial 1 --ttl-days 7 --out /etc/shahrah/tactics.json
shahrah serve-sub --tactics /etc/shahrah/tactics.json
```

Signature: HMAC-SHA256 (the standard library has no Ed25519). It authenticates and expires the
bundle and the serial blocks replay, but whoever verifies must hold the key, so it is not
public-key signing. Phase 2 (own client) should switch to Ed25519.

## 3. paqet crisis path (`paqet`)

[paqet](https://github.com/hanselime/paqet) — MIT, Go, **alpha**. Crafts raw TCP packets
(no SYN handshake) and carries KCP+smux. bbs#570: stable Iran→Hetzner during the Jan 2026
shutdown; useless against BGP withdrawal; carrier-grade NAT often breaks it; needs root on both
ends, so the realistic topology is *Iran-hosted relay → foreign exit*, not phones.

* Exit: `install.sh --host ... --with-paqet 9999` (pinned `v1.0.0-alpha.21`, sha256 verified;
  iptables NOTRACK + RST-drop from upstream; never port 80/443).
* Relay: `shahrah paqet-config client --ip <relay ip> --router-mac <gw mac> --server-ip <exit>
  --key-file paqet.key --out paqet.yaml` and `paqet-config unit --unit-role client`.
* Brain on the relay: `shahrah brain ... --paqet-unit shahrah-paqet-client` starts it on
  `restricted`/`outage`; `prober.probe_socks` measures it through its loopback SOCKS port.

## 4. Social / Instagram quality

`shahrah tuning-profile social && shahrah apply ...` emits only Xray-documented knobs:
`policy.uplinkOnly/downlinkOnly = 0` (policy docs: helps HTTP browsing close connections),
`sockopt.tcpFastOpen` (kernel `tcp_fastopen=3` is already in `print sysctl`),
`sockopt.tcpcongestion = bbr` (docs recommendation), `sockopt.tcpUserTimeout = 10000` (docs
example). Client side: keep Mux off for Vision; Xray docs say Mux reduces handshake latency
but hurts video/downloads, so test it only on XHTTP/CDN profiles.

`brain --social-probe` probes `i.instagram.com` (w=3), `static.cdninstagram.com` (w=2),
`www.instagram.com` (w=2) and a generic 204 URL (w=1) per path; the path is healthy at a
weighted score ≥ 0.75 and ranked by weighted latency.

## 5. Hysteria2 (QUIC/UDP) social path — phase 2

`install.sh --host ... --with-hysteria2 8443 [--hy2-hop 20000-40000]` installs the pinned
Hysteria (`app/v2.13.0`, MIT, sha256 verified), a self-signed certificate, and a server with
**Salamander** obfuscation (packets look like random UDP, not QUIC). Clients pin the leaf
certificate (`pinSHA256`), so no CA or domain is needed. Per-user auth is `label:uuid`.

* Social preset: QUIC windows 2–4 MiB/stream, 5–10 MiB/conn (Hysteria's default is larger;
  smaller windows = less queueing delay), keep-alive 10 s for carrier NAT, and a declared
  10/50 Mbit/s per client so Brutal does not blast lossy mobile links. `--tuning bulk` keeps
  the upstream defaults and uses BBR.
* Port hopping: an iptables `REDIRECT` from the hop range to the listen port; clients rotate
  every 30 s, which defeats per-port UDP throttling.
* Ordering: subscription lists REALITY/TCP first and `hysteria2://` last; the brain treats it
  as an *ordinary* path (`Sidecar(kind="hysteria2")`) — UDP is the first thing an allowlist
  kills, so it never counts as lockdown-capable.

## 6. WaterWall backhaul (Iran relay → exit) — phase 2

`install.sh --role relay --ww-peer <exit ip>` on the Iran server and
`install.sh --host ... --with-waterwall exit --ww-peer <iran ip>` on the exit (copy
`/etc/shahrah/backhaul.key` between them). Users keep their exit REALITY links but dial the
relay IP. The relay does not decrypt user traffic and runs no panel (bbs#675). The leg is a
WaterWall Reality session to a cover site; non-peers are forwarded to that site, and the
tunnel listener only accepts the peer IP. `reverse` mode (default) keeps warm connections
from exit to relay, saving an international handshake on every new Instagram burst.

## 7. paqet as an Oracle path

`brain` sidecars (`"sidecars": [{"name": "rescue", "kind": "paqet", "socks_port": 1080}]`)
make paqet a real path: lockdown-capable, and *on demand* — it only exists while the mode is
restricted/outage (when `--paqet-unit` has started the client), so a stopped client never
marks the system degraded.

## Not done yet

Field validation from Iranian ASNs; real ASN→profile data; per-client derived tactics keys;
Hysteria2/WaterWall/paqet on real servers (loopback smoke only so far).
