# Unified ops console

Shahrah does not fork PasarGuard. The **ops console** (`shahrah ops`) is the shell where
operator tools live next to each other:

| Module | Status | Role |
| --- | --- | --- |
| Status | ready | Shows a brain snapshot when a status JSON path is provided |
| SNI scout | ready | Ranks REALITY target candidates from this vantage |
| SNI watch | ready | Opt-in destination aggregation from the Xray access log |
| Usage (`shahrah usage`) | ready | Per-user bytes from loopback StatsService (independent nodes) |
| Instagram multiplier | ready | Category billing weight from hit shares (`--ig-mult-config`) |
| PasarGuard | external | Users, sales, subscriptions — linked, never vendored |

## Run locally on a box

```bash
TOKEN=$(shahrah ops --print-token)
export SHAHRAH_OPS_TOKEN="$TOKEN"
# loopback only by default — tunnel with SSH if you need remote access:
#   ssh -L 8787:127.0.0.1:8787 root@exit
shahrah ops --token "$TOKEN" --listen 127.0.0.1:8787 \
  --stats-server 127.0.0.1:10085 \
  --access-log /var/log/shahrah/access.log \
  --ig-mult-config /var/lib/shahrah/ig-mult.json
```

Instagram multiplier (`GET/PUT /api/ig-mult`): set `enabled` and `coefficient` (e.g. `0.5`).
With an access log, `?estimate=1` applies the coefficient to each user's StatsService totals
using destination *hit share* as a proxy (no permanent browse archive).

Every `/api/*` call needs header `X-Ops-Token`. Binding to `0.0.0.0` is allowed only as an
explicit opt-in and still requires the token.

## Retarget after a scout

```bash
shahrah sni-scout www.samsung.com www.cloudflare.com www.microsoft.com
shahrah retarget www.samsung.com
shahrah apply --xray-bin /usr/local/bin/xray --config-out /etc/shahrah/xray.json --group shahrah
systemctl restart shahrah-xray
# then refresh brain.json sni= and re-issue client links
```
