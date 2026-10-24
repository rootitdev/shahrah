# Architecture

## Layers

```
clients (ready-made, Android / iOS / Windows / Linux)
   |  base64 subscription of vless:// links   <- links.py
   v
control plane (this repo)
   |  models.py       validated server / user / endpoint data
   |  oracle.py       which paths are healthy, which to prefer, are we being restricted
   |  xray_config.py  renders the server config
   v
data plane: Xray-core  (VLESS + REALITY, TCP/443)
```

Xray is not reimplemented: transports come from a mature core so the traffic fingerprint is
mature too. This repository owns the layer around it.

## Why TCP/443 only

During allowlist shutdowns only DNS (53), HTTP (80) and HTTPS (443) crossed the border, and
Hysteria2/TUIC (UDP) were already unusable from datacenter ranges. Therefore:

- 443 is the pillar; `ServerSettings` refuses other ports unless explicitly overridden.
- 80 is for certificate issuance / redirect; 53 only for last-resort bootstrap.

## Profiles

| Profile | Transport | Notes |
|---|---|---|
| `reality-vision` | raw TCP + XTLS-Vision | Default: best client compatibility. |
| `reality-xhttp` | XHTTP | Needs a recent client core; useful when TCP behaviour is degraded. |

One profile per port. A *path* in the Oracle is a (server, profile) pair a client can use.

## Failover for ready-made clients

Most ready-made clients cannot be told "switch now". The subscription is therefore the
failover channel: `links.build_subscription(..., healthy_ranking=...)` publishes only healthy
endpoints, best first. Clients re-fetch it periodically and drop dead entries by themselves.

## Oracle states

`normal` all healthy, `degraded` some paths down, `restricted` every ordinary path is down but
lockdown-capable ones (CDN-fronted) work (allowlist-style filtering heuristic), `outage` nothing
healthy for several cycles (enable the crisis tier). Leaving a failed path is immediate; moving
back to a better one needs consecutive successes **and** a minimum dwell time, so flaky paths
do not flap.

## Not built yet

1. Prober: real tunnel checks (not just edge TLS) feeding `oracle.step`.
2. One-command installer for Debian/Ubuntu (Xray install, key generation, firewall, systemd).
3. Management layer: root admin, sales managers and customers on top of PasarGuard.
4. CDN-fronted XHTTP profile (needs a TLS-terminating reverse proxy).
5. Leak-proof dedicated clients (kill-switch, DNS/IPv6/WebRTC leak protection).

## Burn detection and rotation

A server whose IP or SNI is blocked inside Iran still works from everywhere else, so one vantage
point cannot tell *burned* from *down*. `shahrah.burn` compares two vantages:

| field (inside) | control (outside) | verdict |
| --- | --- | --- |
| ok | any | healthy |
| fail | ok | **blocked** (burn candidate) |
| fail | fail | down (repair, do not rotate) |
| fail | unknown | unknown (never declared blind) |

Guards: `burn_after` consecutive blocked cycles are needed, and if *every* endpoint is blocked
at once it is reported as network-wide (shutdown / allowlist mode) instead of burning anything.

Wiring (no third-party service is required):

1. On a free network run `shahrah brain --config brain.json --write-report /var/www/report.json`
   and publish that file over HTTPS (any static host).
2. On the field vantage run `shahrah brain ... --control-report https://host/report.json
   --on-burn /etc/shahrah/on-burn`.
3. `on-burn` is an operator executable called (no shell) with the burned endpoint names as
   arguments. It is where provider-specific rotation lives: allocate a new IP, re-point DNS,
   add the endpoint to the brain config. Shahrah deliberately ships no cloud-provider code.

Stale (> `--control-max-age`) or unreachable control reports mean "unknown", which never
produces a burn.

## CDN-fronted XHTTP (crisis layer)

When direct server IPs are blocked, a CDN edge often stays reachable. The `cdn-xhttp` listener
is plain VLESS over XHTTP (`security: none`) meant to sit **behind** a CDN or a TLS reverse
proxy that terminates TLS:

    client --TLS--> CDN edge (443) --HTTP--> origin listener (e.g. :8080, plain XHTTP)

* Added as an extra listener: `shahrah listener add 8080:cdn-xhttp:cdn.example.com`. The path is
  generated (unguessable) unless given; `...:PATH:http` makes clients use plain HTTP to the edge.
* The origin speaks plain HTTP, so the long random path is its only gate: paths shorter than 9
  characters are rejected, and a wrong path is verified by an end-to-end test to be refused.
* `packet-up`/`stream-up`/`auto` only; `stream-one` is refused behind a CDN because CDNs
  buffer or cut single long streams.
* The primary listener must stay REALITY. CDN endpoints are listed last and flagged
  `lockdown_capable` (assumption to confirm in the field tests).
* Restrict the origin port in the firewall to your CDN's address ranges. Shahrah ships no CDN
  range lists because they change; the operator applies them.
* No CDN account, domain or API credential is stored anywhere in the repo.

## Local load evidence (`pytest -m load`)

Run on one developer machine with a real Xray REALITY node, a client and a local echo target:

* 300 concurrent tunnels all completed an echo exchange (setup p95 about 5.6 s on that machine,
  dominated by REALITY borrowing a real handshake from the cover site for every new connection;
  pick a cover site that is fast from the *server*, `xray` has no cache for it).
* With `conn_idle_s=30` every idle tunnel was closed by the node within the limit, the target saw
  0 open connections, and the clients observed the closure (no half-open "dead" sockets).
* The node kept serving a fresh wave afterwards.
* A user cannot reach loopback/LAN services behind the node: Shahrah's own routing rule blocks
  private ranges and Xray 26 additionally refuses them inside the freedom outbound.

What this does **not** prove: behaviour with 1000-3000 *real* users on the Iranian internet,
vanished peers on lossy mobile links (TCP keepalive is configured but cannot be simulated on
loopback), CPU/memory at that scale, or throughput. Those need the server phase.

## Standby rotation (spare IPs / domains)

Shahrah ships no cloud-provider code, so a replacement IP or domain is provisioned **ahead of
time** by the operator and registered as a normal endpoint and panel host, then listed under
`"standby": ["spare-1", ...]` in `brain.json` (promotion order). Spares are probed like any
other endpoint but stay hidden from clients (their panel host stays disabled) until:

* an endpoint is declared burned: one healthy spare is promoted per burned endpoint; or
* no non-standby endpoint is healthy at all (plain failover).

When a burn is forgiven the spare is demoted again. `--on-burn` remains available for
operators who also want to provision new spares automatically.

## Field note: TCP/53 from Iran

On at least one measured Iran→foreign path (2026-10), outbound TCP to the exit's port 53 was
filtered while 80 and 443 stayed open. `--multi-port` still installs a 53 listener for crisis
scenarios and other networks, but operators should verify `timeout 3 bash -c 'echo >/dev/tcp/EXIT/53'`
from an Iran vantage before advertising that port to clients. Shahrah's crisis ranking already
prefers 443 then 80.
