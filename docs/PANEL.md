# Management panel (PasarGuard)

Shahrah does **not** reimplement user, plan and billing management. It uses
[PasarGuard](https://github.com/PasarGuard/panel) (AGPL-3.0, actively maintained) as the
system of record and only *steers* it. Shahrah talks to it exclusively over its public REST
API, never imports its code, and stays independent of its licence and release cycle.

## Who does what

| Person | Where | How |
|---|---|---|
| **Root admin** | Panel UI | PasarGuard's built-in *owner* role: everything. |
| **Sales manager** | Panel UI | `sales_manager_role(...)`: creates and manages **only their own** customers, only from allow-listed plan templates, within caps on users, traffic and duration. No access to hosts, nodes, settings or other managers' customers. |
| **Customer** | Subscription page | Not a panel admin. Sees plan, usage and expiry on the page behind their subscription link and imports that link into any ready-made client. |
| **Shahrah brain** | REST API key | `brain_role()`: may list/reorder/disable hosts and read nodes. Nothing else, so a leaked key cannot reach users or money. |

The role payloads in `shahrah.roles` are checked against PasarGuard's real pydantic models
(`PASARGUARD_SRC=<checkout> pytest tests/test_roles.py`), so a panel upgrade that changes the
schema is caught by a failing test instead of in production.

## How the brain steers the panel

```
prober (real tunnel requests) -> oracle (hysteresis, modes) -> ranking
        -> panel.plan_sync -> bulk enable/disable + priority updates -> subscriptions
```

Each Shahrah path is mapped to a panel host by its unique **remark**. Ready-made clients
refresh their subscription and stop seeing dead hosts; healthy ones come first (PasarGuard
sorts hosts by ascending `priority`).

Safety rules (unit-tested):

- **No healthy path -> change nothing.** A blind or mis-placed prober can never empty
  everyone's subscription.
- Only hosts mapped to a Shahrah path are touched; anything managed by hand stays as is.
- Writes are minimal and idempotent; enabling happens before disabling.
- The API key travels in `X-Api-Key`, is refused over plain `http` to a remote host, is
  never printed, and loopback requests never go through a system proxy.

## Setting it up

1. In PasarGuard create the *brain* role from `brain_role()` (`POST /api/admin-role`), an admin
   with that role, and an API key for it.
2. Create one sales role per tier from `sales_manager_role(...)` with the plan template ids it
   may sell.
3. Create one panel host per Shahrah path with a **unique remark**.

## Not covered here

Online payment collection and a Telegram sales bot are intentionally outside this layer:
PasarGuard has no payments, and they can be added later on top of its REST API without
touching the VPN core.
