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
