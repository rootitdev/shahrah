# Single control plane (item 3)

Do **not** run Shahrah **brain** failover and vpn-infra-kit **`vpn-failover`** timers on the
same production exit. They both steer paths and panel hosts through different mechanisms.

| Choose one | When | Steering mechanism |
|---|---|---|
| **Shahrah brain** | Standalone `deploy/install.sh` exit or relay; PasarGuard via `shahrah panel` | `brain.json` + Oracle + REST panel updates |
| **vpn-infra-kit** | Full kit install with Iran node + `PATH_PRIORITY` / `vpn_failover.py` | Health JSON + PasarGuard `put_selector` every 15s |

Mixing both causes conflicting host enable/disable, duplicate health probes, and unclear
source of truth during outages.

**Recommended defaults**

- New Shahrah-only exit: install brain after panel bootstrap; skip kit failover entirely.
- Kit-based deployment: use kit timers only; do not enable `shahrah-brain` on the same host.

Shahrah **`path-web`** (`deploy/panels/path-web`) drives `shahrah backhaul`, not PasarGuard
selectors — use it for WaterWall path lock/auto on Iran or exit. It does not replace brain.

Optional vpn-infra-kit `path-web` (Xray `put_selector`) is **only** for full kit installs.
Do not mix kit path-web with Shahrah backhaul on the same host unless you coordinate manually.

See also [OPERATOR.md](OPERATOR.md) and [PANEL.md](PANEL.md).
