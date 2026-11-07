# Pilot measurement worksheet (hourly VPS) — item 8

Copy this table into your runbook. Fill **before** buying fleet capacity.

## Suggested commands (run on exit after `deploy/install.sh`)

```bash
shahrah capacity --users 500 --json
shahrah load-test --connections 200 --json   # needs xray + internet for REALITY cover
shahrah probe --config /var/lib/shahrah/brain.json --endpoint exit-443 --wave 50 --json
```

From an Iranian vantage (separate machine):

```bash
shahrah probe --config brain.json --endpoint exit-443 --wave 100 --json
# optional throughput: curl -x socks5h://127.0.0.1:PORT -o /dev/null -w '%{speed_download}\n' https://example.com/1mb.bin
```

Persian printable form: [PILOT-MEASUREMENTS-fa.md](PILOT-MEASUREMENTS-fa.md)
