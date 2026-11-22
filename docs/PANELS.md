# Shahrah web panels (native)

All panels live under `deploy/panels/` in this repo — **no vpn-infra-kit checkout**.  
Installer: `deploy/install-panels.sh` with **`INSTALL_ROLE`**.

## Where to install

| Panel | URL path | Role | Why |
|-------|----------|------|-----|
| **settle** + **pay** | `/settle/` `/pay/` | **master** | PasarGuard REST only |
| **mysub** (rootit) | `/mysub/` `/admin` | **master** | Subscription recovery via panel API |
| **path-web** | `/path/` | **relay** or exit w/ WaterWall | `shahrah backhaul` on same host |
| **sni-watch** | `/watch/` | **relay** or **exit** | Needs local Xray `access.log` |
| **ig-mult** | `/ig/` | **exit** | Instagram multiplier beside Xray/docker |

```bash
# Master (PasarGuard on this host)
sudo INSTALL_ROLE=master \
  SHAHRAH_PANEL_URL=https://127.0.0.1:8000 \
  SHAHRAH_PANEL_API_KEY='pg_key_...' \
  PANEL_BASE=https://panel.example.com \
  ./deploy/install-panels.sh

# Iran relay
sudo INSTALL_ROLE=relay PANEL_BASE=https://panel.example.com PANELS=path,watch \
  ACCESS_LOG=/var/log/shahrah/access.log ./deploy/install-panels.sh

# Foreign exit
sudo INSTALL_ROLE=exit PANEL_BASE=https://panel.example.com PANELS=ig,watch ./deploy/install-panels.sh
```

`INSTALL_ROLE=auto` picks master / relay / exit from running units.

## Secrets

`/root/.vpn-secrets/.env` (0600):

```bash
SHAHRAH_PANEL_URL=https://panel.example.com:443
PANEL_API_KEY=pg_key_...
```

`deploy/lib/panel_master_env.sh` feeds `PANEL_API_BASE` into settle config on the master.

## Ports (loopback)

| Service | Default |
|---------|---------|
| ig | `127.0.0.1:8786` |
| settle/pay | `127.0.0.1:8789` |
| watch | `127.0.0.1:8785` |
| path | `127.0.0.1:8791` |
| mysub (rootit) | `127.0.0.1:8790` |
| shahrah ops | `127.0.0.1:8787` |
| serve-sub | `127.0.0.1:8788` |

See `deploy/Caddyfile.example` for TLS reverse-proxy paths.

## Multi-exit hosts

`shahrah panel fleet-plan` / `fleet-apply` on the master — [RELAY-PANEL-HOSTS-fa.md](RELAY-PANEL-HOSTS-fa.md), `deploy/fleet.example.json`.

## Built-in (not under deploy/panels/)

- `shahrah ops` — JSON API for stats / ig config
- `shahrah settle-hook` — HMAC webhook (alternative to settle-web HTML)