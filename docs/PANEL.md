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

Only the panel *owner* key is used for the one-time setup; pass it through the environment, never
on the command line (arguments are visible to every local user).

```bash
export SHAHRAH_PANEL_URL=https://panel.example.org
export SHAHRAH_PANEL_API_KEY=<owner key>

# 1. brain role + the unlimited account the prober connects with (needs the group id that
#    grants access to your REALITY inbound). Prints the probe user's uuid for brain.json.
shahrah panel bootstrap --probe-group-id 1

# 2. one sales role per tier, limited to the plan templates it may sell
shahrah panel sales-role --name sales-basic --template-id 3 --max-users 100
```

Both commands are idempotent and never modify an existing role or user.

Then, in the panel UI: create an admin with the `shahrah-brain` role and an API key for it, and
one host per Shahrah path with a **unique remark**.

On the machine that runs the brain (it only makes outbound connections):

```bash
sudo ./deploy/install.sh --role brain
# write /etc/shahrah/brain.json  (endpoints, probe_user from step 1, remarks)
# put SHAHRAH_PANEL_URL and the *brain* API key into /etc/shahrah/brain.env (0600)
sudo systemctl start shahrah-brain
```

`brain.json` holds public routing data only (hosts, ports, public keys, short ids); the probe
user's uuid must also be a user on every exit it probes, which step 1 guarantees when the exits
are panel nodes.

## Not covered here

Online payment collection and a Telegram sales bot are intentionally outside this layer:
PasarGuard has no payments, and they can be added later on top of its REST API without
touching the VPN core.

## Leak resistance for ready-made clients

```bash
shahrah panel client-template            # uploads "shahrah-leak-resistant", not made default
shahrah panel client-template --make-default   # explicit: applies to ALL users' JSON configs
```

The template (`shahrah.client_template`) is checked with a real Xray binary merged exactly the way the
panel merges it. It tunnels DNS (DoH as plain `https://` URLs, no fallback to the local resolver),
never resolves destinations on the device, blocks IPv6 in the client and keeps local proxy ports on
loopback. The server side resolves names itself over DoH and has TCP keepalive plus idle/handshake
limits so vanished mobile clients do not leave dead connections behind.

What a template **cannot** do: a browser's WebRTC bypasses a SOCKS/HTTP proxy and can reveal the real
address in *proxy mode*. Use the client's TUN/VPN mode or disable WebRTC in the browser. A dedicated
client with a kill-switch is a later phase; until then this remains a documented limitation.