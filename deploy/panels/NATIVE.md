# Native Shahrah panels

These directories are **first-party** copies maintained in the shahrah repo:

| Directory | Service | Systemd unit |
|-----------|---------|--------------|
| `settle-web/` | Reseller settle + customer pay | `settle-web` |
| `ig-mult-web/` | Instagram traffic multiplier UI | `ig-mult-web` |
| `sni-watch/` | SNI access-log viewer | `sni-watch` |
| `path-web/` | Backhaul path UI (`shahrah backhaul`) | `path-web` |
| `bin/` | `instagram-multiplier` CLI for ig panel | — |

**mysub** is not a separate app: `deploy/install-panels.sh` with `PANELS=mysub` runs `deploy/install-rootit.sh` (`shahrah rootit`).

Do not clone vpn-infra-kit for production. If you need a one-off diff, compare against your old kit checkout, then patch here.