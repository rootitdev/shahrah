# Security

Shahrah is designed so a public GitHub clone never contains deployment facts.

## Never commit

* Server IPs, domains, REALITY private keys, panel API keys, ops/settle/sub secrets
* `state.json`, `brain.json`, `*.env`, access logs
* Private infrastructure repo names or deployment inventory (hygiene tests reject known leaks)

## Operator habits

* Put secrets in `EnvironmentFile=` units (`brain.env`, `sub.env`), never on `ExecStart` argv
* Rotate root / panel / sub path secrets after any paste into chat or tickets
* Keep `shahrah ops` and `serve-sub` on loopback; reach them over SSH tunnels
* Enable access logs only when you need SNI watch / Instagram multiplier estimates

## Reporting

If you find a vulnerability in this repository (not in a private deployment), open a
private security advisory on the GitHub repo or contact the maintainers listed there.
