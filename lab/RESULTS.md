# Lab results

Generated 2026-11-04 14:42 +0330 by `lab/run.sh` (WSL2 netns, see README for limits).
Workload per cell: 20 small HTTPS GETs (2 KB, 5 concurrent) + one 2 MB fetch through the path to the cover server. Times in ms.

| profile | reality-vision | reality-xhttp | reality-domain | relay-ww | hysteria2 | paqet |
|---|---|---|---|---|---|---|
| open | ✅ 100% ttfb 10.7 p50 10.7 p95 22.0, 2MB 0.02s | ✅ 100% ttfb 8.9 p50 9.1 p95 32.0, 2MB 0.03s | ✅ 100% ttfb 9.3 p50 9.5 p95 13.2, 2MB 0.02s | ✅ 100% ttfb 14.7 p50 14.8 p95 39.1, 2MB 0.02s | ✅ 100% ttfb 8.4 p50 8.5 p95 16.4, 2MB 0.34s | ✅ 100% ttfb 121.0 p50 121.9 p95 122.8, 2MB 0.15s |
| sni-dpi | ❌ | ✅ 100% ttfb 6.8 p50 7.0 p95 9.6, 2MB 0.03s | ❌ | ❌ | ✅ 100% ttfb 8.3 p50 9.0 p95 12.8, 2MB 0.34s | ✅ 100% ttfb 120.8 p50 121.6 p95 123.4, 2MB 0.22s |
| udp-block | ✅ 100% ttfb 8.5 p50 8.7 p95 11.9, 2MB 0.01s | ✅ 100% ttfb 7.8 p50 8.1 p95 9.5, 2MB 0.03s | ✅ 100% ttfb 9.9 p50 10.3 p95 12.5, 2MB 0.02s | ✅ 100% ttfb 13.7 p50 14.3 p95 1012.6, 2MB 0.01s | ❌ | ✅ 100% ttfb 121.6 p50 122.2 p95 123.2, 2MB 0.17s |
| udp-throttle | ✅ 100% ttfb 7.8 p50 8.0 p95 10.3, 2MB 0.01s | ✅ 100% ttfb 7.3 p50 7.9 p95 9.6, 2MB 0.02s | ✅ 100% ttfb 8.7 p50 8.9 p95 11.9, 2MB 0.01s | ✅ 100% ttfb 12.5 p50 12.9 p95 14.8, 2MB 0.01s | ❌ | ✅ 100% ttfb 120.8 p50 121.4 p95 122.8, 2MB 0.17s |
| allowlist-ip | ❌ | ❌ | ❌ | ✅ 100% ttfb 10.1 p50 10.2 p95 1053.0, 2MB 0.01s | ❌ | ❌ |
| icmp-only | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| dns-poison | ✅ 100% ttfb 8.7 p50 8.8 p95 11.0, 2MB 0.02s | ✅ 100% ttfb 8.4 p50 8.8 p95 12.3, 2MB 0.04s | ❌ | ✅ 100% ttfb 11.8 p50 12.4 p95 38.9, 2MB 0.02s | ✅ 100% ttfb 6.9 p50 7.2 p95 10.4, 2MB 0.34s | ✅ 100% ttfb 120.7 p50 121.6 p95 122.6, 2MB 0.18s |
| lossy-mobile | ✅ 100% ttfb 633.2 p50 655.8 p95 1610.0, 2MB 2.19s | ✅ 100% ttfb 452.1 p50 452.2 p95 643.1, 2MB 0.92s | ✅ 100% ttfb 877.7 p50 878.0 p95 2630.1, 2MB 2.26s | ✅ 100% ttfb 642.2 p50 642.3 p95 1652.0, 2MB 2.25s | ✅ 100% ttfb 331.8 p50 334.3 p95 627.4, 2MB 1.44s | ✅ 100% ttfb 395.2 p50 395.5 p95 580.7, 2MB 1.29s |
| shutdown | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

## Brain / oracle failover

| censor profile | expected mode / active | observed | cycles | pass |
|---|---|---|---|---|
| open | normal / reality-vision | normal / reality-vision | 3 | ✅ |
| udp-block | degraded / reality-vision | degraded / reality-vision | 3 | ✅ |
| allowlist-ip | restricted / relay-ww | restricted / relay-ww | 3 | ✅ |
| shutdown | outage / None | outage / relay-ww | 3 | ✅ |
| open | normal / reality-vision | normal / reality-vision | 4 | ✅ |
