# Master / relay / multi-exit topology

Shahrah targets this production shape:

```
users ──► Iran relay (REALITY :443, no user DB)
              │
              ├── backhaul path 1..N (WaterWall, failover)
              ▼
         Exit NL / US / TN … (Xray + PasarGuard node)
              ▼
         Internet

master (optional dedicated host) ──► PasarGuard panel (users, subs, billing)
                REST ──► each exit core/node
```

## Roles

| Role | Install | Holds users? | Xray for clients? |
|------|---------|--------------|-------------------|
| **master** | `./deploy/install.sh --role master` | Yes (PasarGuard) | No |
| **exit** | `./deploy/install.sh --host …` or panel attach scripts | Via PG node | Yes |
| **relay** | `./deploy/install.sh --role relay --ww-peer EXIT …` | No | Front only (WaterWall) |
| **brain** | `./deploy/install.sh --role brain` | No | Probes + panel steering |

Master can live on the same VPS as one exit in small setups; split is recommended when the panel needs a stable IP and exits rotate.

## Multiple exits

1. **PasarGuard hosts** — one host per country/exit; subscription lists multiple `vless://` entries; `shahrah brain` orders healthy hosts.
2. **Iran multi-peer** — `shahrah relay peer-add` (distinct `user_port` per exit on one Iran IP). See `relay_peers.py` and [OPERATOR.md](OPERATOR.md).

User UUIDs are **per exit** unless you manage sync in the panel; Shahrah does not mirror users across exits automatically.

## Backhaul (not the user path)

User path is **REALITY**; WaterWall is only Iran↔exit. Failover: [BACKHAUL.md](BACKHAUL.md), UI: `deploy/panels/path-web`, timer: `shahrah-backhaul-failover.timer`.

## Panels (native, role-based)

```bash
# Master only (typical)
sudo INSTALL_ROLE=master PANEL_BASE=https://panel.example.com \
  SHAHRAH_PANEL_URL=... SHAHRAH_PANEL_API_KEY=... \
  ./deploy/install-panels.sh

# Iran relay
sudo INSTALL_ROLE=relay PANEL_BASE=... ./deploy/install-panels.sh

# Exit
sudo INSTALL_ROLE=exit PANEL_BASE=... ./deploy/install-panels.sh
```

See [PANELS.md](PANELS.md). Fleet: `shahrah panel fleet-plan --file fleet.json`.

Do **not** run vpn-infra-kit `vpn-failover` and Shahrah brain on the same production host ([CONTROL-PLANE.md](CONTROL-PLANE.md)).

Live Webdade checklist: [PRODUCTION-WEBDADE.md](PRODUCTION-WEBDADE.md).

## WARP

Removed from the installer. Legacy `state.json` warp blocks still load; module lives in `src/shahrah/warp.py` for compatibility only. See `contrib/optional/WARP.md`.