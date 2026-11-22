# Lab results

Generated 2026-11-04 15:46 +0330 by `lab/run.sh` (WSL2 netns, see README for limits).
Workload per cell: 20 small HTTPS GETs (2 KB, 5 concurrent) + one 2 MB fetch through the path to the cover server. Cell: small p50/p95 ms · 2 MB seconds. Fresh client processes per row. `intl:` rows censor the international gateway (client leg open).

| profile | reality-vision | reality-xhttp | reality-domain | relay-ww | cdn-xhttp | hysteria2 | hysteria2-plain | paqet |
|---|---|---|---|---|---|---|---|---|
| open | ✅ 10/22 · 0.01s | ✅ 9/30 · 0.03s | ✅ 9/11 · 0.01s | ✅ 10/1039 · 0.01s | ✅ 80/131 · 0.11s | ✅ 7/9 · 0.34s | ✅ 9/10 · 0.34s | ✅ 122/123 · 0.17s |
| sni-dpi | ❌ | ❌ | ❌ | ❌ | ✅ 77/96 · 0.15s | ✅ 8/9 · 0.34s | ❌ | ✅ 122/123 · 0.19s |
| udp-block | ✅ 10/30 · 0.01s | ✅ 8/32 · 0.03s | ✅ 9/11 · 0.01s | ✅ 11/1037 · 0.01s | ✅ 77/126 · 0.16s | ❌ | ❌ | ✅ 122/123 · 0.18s |
| udp-throttle | ✅ 10/29 · 0.01s | ✅ 8/29 · 0.03s | ✅ 8/10 · 0.01s | ✅ 12/28 · 0.01s | ✅ 80/105 · 0.11s | ❌ | ✅ 204/260 · 6.62s | ✅ 122/123 · 0.17s |
| allowlist-ip | ❌ | ❌ | ❌ | ✅ 11/1029 · 0.01s | ❌ | ❌ | ❌ | ❌ |
| icmp-only | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| dns-poison | ✅ 12/44 · 0.01s | ✅ 8/26 · 0.03s | ❌ | ✅ 12/14 · 0.02s | ✅ 69/139 · 0.15s | ✅ 6/9 · 0.34s | ✅ 7/12 · 0.34s | ✅ 122/123 · 0.17s |
| lossy-mobile | ✅ 643/1633 · 3.09s | ✅ 336/496 · 1.89s | ✅ 719/3807 · 3.29s | ✅ 637/1815 · 2.23s | ✅ 591/1142 · 17.07s | ✅ 329/468 · 1.44s | ✅ 331/598 · 1.15s | ✅ 365/411 · 1.27s |
| shutdown | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| sni-dpi-strict | ❌ | ❌ | ❌ | ❌ | ✅ 69/147 · 0.16s | ❌ | ❌ | ✅ 122/124 · 0.16s |
| intl:sni-dpi | ❌ | ❌ | ❌ | ✅ 13/38 · 0.01s | ✅ 72/123 · 0.16s | ✅ 7/10 · 0.35s | ❌ | ✅ 122/124 · 0.17s |
| intl:udp-block | ✅ 9/25 · 0.01s | ✅ 9/31 · 0.03s | ✅ 8/9 · 0.01s | ✅ 23/1009 · 0.01s | ✅ 76/144 · 0.1s | ❌ | ❌ | ✅ 122/124 · 0.17s |
| intl:allowlist-ip | ❌ | ❌ | ❌ | ❌ | ✅ 93/127 · 0.11s | ❌ | ❌ | ❌ |
| intl:lossy-mobile | ✅ 654/1644 · 2.39s | ✅ 399/707 · 1.99s | ✅ 630/899 · 2.71s | ✅ 486/1069 · 2.4s | ✅ 619/967 · 22.84s | ✅ 332/464 · 1.47s | ✅ 333/637 · 0.93s | ✅ 407/531 · 1.34s |

## Brain / oracle failover

| censor profile | expected mode / active | observed | cycles | pass |
|---|---|---|---|---|
| open | normal / reality-vision | normal / reality-vision | 3 | ✅ |
| udp-block | degraded / reality-vision | degraded / reality-vision | 3 | ✅ |
| allowlist-ip | restricted / relay-ww | restricted / relay-ww | 3 | ✅ |
| intl:allowlist-ip | restricted / cdn-xhttp | restricted / cdn-xhttp | 3 | ✅ |
| shutdown | outage / None | outage / cdn-xhttp | 3 | ✅ |
| open | normal / reality-vision | normal / reality-vision | 4 | ✅ |
