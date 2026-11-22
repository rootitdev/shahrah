# Iran client + matching exit inbounds (Webdade)

Path: **client → Iran relay `203.0.113.20` / `entry.example.com` → WaterWall → NL Xray**.

## Geo files (required)

Replace Loyalsoldier / CN packs with Chocolate4U Iran rules:

- https://github.com/Chocolate4U/Iran-v2ray-rules/releases  
  (`geosite.dat`, `geoip.dat` into the client `bin/` / geo folder)

Do **not** use `geosite:cn`, `geoip-only-cn-private.dat`, alidns / doh.pub / 360 DNS.

## Files

| File | Role |
|------|------|
| `client-reality-vision-balanced.json` | Main: Vision×3 + burstObservatory + leastPing balancer |
| `client-reality-xhttp.json` | Reality + XHTTP (port 53, path `/shahrah`) |
| `client-trojan-tls.json` | Trojan+TLS to NL (crisis / direct exit; not via WW) |
| `client-ss2022.json` | Shadowsocks-2022 to NL |
| `client-ios-reality-vision.json` | Minimal iOS-friendly Vision (fp `ios`, no mux) |
| `server-inbounds.json` | Matching NL inbounds (Vision already live; others to enable) |

Shared REALITY params (must stay identical client↔server):

- `dest` / `serverNames` / SNI: `www.cloudflare.com`
- `shortIds`: `45a83332119989cd`
- public key: `-LsvFSSWY2t6LMyP23GAhk2I-64S3x6VakVCoVUQ9iM`
- Vision `flow`: `xtls-rprx-vision`
- network: **`tcp`** (not `raw`)

UUID in examples: `webdade-test` → `12b29642-dd65-427b-98a1-4d02ed472150` (change per user).

## Notes

- Vision / XHTTP address the **Iran entry** (relay). Trojan / SS-2022 examples point at **NL** `203.0.113.11` until a separate WW path exists for them.
- After editing server inbounds: `shahrah apply` / restart Xray and open ufw ports.
- Re-upload panel client template after code change:  
  `shahrah panel client-template --update --make-default`
