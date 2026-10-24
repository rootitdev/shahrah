# Unified ops console

Shahrah does not fork PasarGuard. The **ops console** (`shahrah ops`) is the shell where
operator tools live next to each other:

| Module | Status | Role |
| --- | --- | --- |
| Status | ready | Shows a brain snapshot when a status JSON path is provided |
| SNI scout | ready | Ranks REALITY target candidates from this vantage |
| SNI watch | planned | Observation of destinations (product requirement; opt-in) |
| Instagram multiplier | planned | Category accounting for billing, without browsing logs |
| PasarGuard | external | Users, sales, subscriptions — linked, never vendored |

## Run locally on a box

```bash
TOKEN=$(shahrah ops --print-token)
export SHAHRAH_OPS_TOKEN="$TOKEN"
# loopback only by default — tunnel with SSH if you need remote access:
#   ssh -L 8787:127.0.0.1:8787 root@exit
shahrah ops --token "$TOKEN" --listen 127.0.0.1:8787
```

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
