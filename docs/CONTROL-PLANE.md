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

Optional kit panels (`path-web`) are **not** a second data-plane controller; they only expose
manual path lock for the kit core. Shahrah `shahrah ops` is separate again — use it for
status/usage, not alongside kit failover unless you accept manual coordination.

See also [OPERATOR.md](OPERATOR.md) and [PANEL.md](PANEL.md).
