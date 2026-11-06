# Kit panels (ig / settle / watch)

Optional web UIs vendored from [vpn-infra-kit](https://github.com/rootitdev/vpn-infra-kit) under `deploy/panels/`.
They are **not** started by `deploy/install.sh`. Install with:

```bash
sudo PANEL_BASE=https://panel.example.com:2096 ./deploy/install-panels.sh
```

Select a subset: `PANELS=ig,settle` or `PANELS=watch`.

## What you get

| Path | Unit | Default listen | Role |
|------|------|----------------|------|
| `/ig/` | `ig-mult-web` | `127.0.0.1:8786` | Exit beside PasarGuard — Instagram traffic multiplier UI |
| `/settle/` + `/pay/` | `settle-web` | `127.0.0.1:8789` | Exit — sales / settlement + customer pay portal |
| `/watch/` | `sni-watch` | `127.0.0.1:8785` | Node with Xray access.log (often Iran) — selected-user SNI watch |

Passwords land in `/etc/<panel>/admin.pass` (mode 600). Put TLS in front (Caddy/nginx); see `deploy/Caddyfile.example`.

## Not included

- **path-web** (kit backhaul switcher) — use `shahrah ops` for service status.
- Auto-run from the node installer — only a Next-steps hint is printed.

## Ports vs other Shahrah loopbacks

| Service | Default |
|---------|---------|
| `shahrah serve-sub` | `:8788` |
| `shahrah ops` | `:8787` |
| `shahrah rootit` / `settle-hook` | `:8790` |
| kit ig / settle / watch | `:8786` / `:8789` / `:8785` |

Override with `LISTEN_IG`, `LISTEN_SETTLE`, `LISTEN_WATCH`.

## Env cheat sheet

```bash
PANEL_BASE=https://panel.example.com:2096   # required
PANELS=ig,settle,watch                      # default all three
PANEL_NGINX_APPLY=n                         # default; set y to patch nginx conf
ACCESS_LOG=/var/log/shahrah/access.log      # watch only
AUTH_USER_IG=ig AUTH_PASS_IG=...            # optional; empty pass → random
AUTH_USER_SETTLE=settle AUTH_PASS_SETTLE=...
AUTH_USER_WATCH=watch AUTH_PASS_WATCH=...
SHAHRAH_PANEL_API_KEY=...                   # optional; written for settle /pay/ if secrets file lacks PANEL_API_KEY
```

## Related Shahrah built-ins

- **`shahrah ops`** — status / SNI scout / ig-mult config JSON API (not the kit `/ig/` UI).
- **`shahrah settle-hook`** — HMAC payment webhook (not the kit settle/pay HTML).
- **`shahrah sni-watch` / access-log** — CLI aggregation; kit `/watch/` is the full UI + systemd collector.

Enable access logging before watch is useful:

```bash
shahrah access-log /var/log/shahrah/access.log
shahrah apply --xray-bin /usr/local/bin/xray --config-out /etc/shahrah/xray.json
systemctl restart shahrah-xray
```
