# Production topology (example — replace with your hosts)

> Template for multi-role Webdade-style deploy. Do **not** commit live IPs, API keys, or panel URLs to a public repo.

## Roles (example)

| Host | IP (example) | Production services |
|------|--------------|---------------------|
| **DE master** | `203.0.113.10` | PasarGuard (DB + API), Caddy, settle, mysub (rootit), backups |
| **NL exit** | `203.0.113.11` | PasarGuard **node** (`nl-exit` / core `shahrah-nl`), WaterWall, **ig-mult** + **sni-watch** |
| **GE exit** | `203.0.113.12` | PasarGuard **node** (`ge-exit` / core `shahrah-ge`); extra exit / 🇩🇪 hosts |
| **IR relay** | `203.0.113.20` | WaterWall `:443` + `:53`, shahrah-brain, path-web |

Users enter via **IR:443** (or `entry.example.com`); backhaul reaches **NL Xray** owned by the panel node.

### Architecture rule (keep it clean)

| Concern | Where | How |
|---------|-------|-----|
| Users / groups / hosts / cores | **DE** PasarGuard | REST API only — system of record |
| Xray exit | **NL** `pg-node` Docker | `XRAY_EXECUTABLE_PATH` → static Go launcher (image has no Python) |
| Access log | **NL** bind-mounted | launcher forces `log.access` → `/var/lib/pg-node/logs/access.log`; compose also mounts `/var/lib/shahrah` + `/var/log/xray` |
| Instagram multiplier | **NL** next to Xray | CLI/UI lookup via Panel API (`SHAHRAH_PANEL_*`); never docker/SSH sqlite |
| SNI watch | **NL** same host as access.log | reads live log (+ optional GE mirror); `sni-watch-resolve.timer` maps username→numeric Xray email via Panel API |
| Brain steering | **IR** | Panel API; remarks must match host names |
| Web UI edge | **DE** Caddy | reverse tunnels `/ig` `/watch` ← NL, `/path` ← IR |

Do **not** `docker exec pasarguard` from the exit, and do **not** SSH to the master sqlite for routine panels. Scripts and state stay on the role that owns them (panel on DE, traffic tools on NL, brain on IR).

## PasarGuard node (exit)

- Core on panel: **`shahrah-nl`** (**in-main** and **in-53** are both VLESS REALITY **xhttp** — PasarGuard nodes do not push per-user `xtls-rprx-vision` flow today, so Vision TCP probes/users would fail while xhttp works).
- Exit runs `pg-node` + `pg-node-service`; panel reaches **`203.0.113.11:62050`** (ufw allow).
- Access log for watch: install launcher (rebuilds Go binary, fixes compose mounts, points sni-watch), then **reconnect** node in panel:
  `sudo FORCE_REBUILD=1 bash deploy/pg-node/install-xray-access-launcher.sh`
- **GE exit:** run the same launcher on the second node; on NL enable `sni-watch-ge-log-relay` to tail GE `access.log` into `ACCESS_LOGS` (see `deploy/panels/sni-watch/`).
- Live log path: `/var/lib/pg-node/logs/access.log` (bind-mounted). Compat symlink: `/var/lib/shahrah/access.log`.
- Hybrid bridge **off** when `/etc/shahrah/pg-node-active` exists:
  - `shahrah-xray` disabled
  - `shahrah-sync-users.timer` disabled

Re-install node: [PasarGuard node script](https://docs.pasarguard.org/en/node/) then register in panel with cert + API key from `/var/lib/pg-node/certs/`.

## Hosts and nl-53

- **`nl-443`** / **`nl-443-dl`**: production entry (IR IP / domain).
- **`nl-53`**: VLESS **xhttp** on port **53** via a **second WaterWall chain** (`config-53.json`, tunnel **8553** → NL `127.0.0.1:53`). Brain maps `nl-53` again in `remarks`.

## Brain (Iran)

- Probe user **`shahrah_probe`** must exist in the panel (same UUID as `brain.json`). Re-run:
  `shahrah panel bootstrap --probe-group-id <id> --probe-username shahrah_probe`
- Steering: healthy paths get enabled / priority; unhealthy hosts disabled (not manual “turning off”).

## Extra inbounds (NL node core `shahrah-nl`)

| Tag | Protocol | Port | Client host | Path |
|-----|----------|------|-------------|------|
| `in-main` | VLESS REALITY xhttp | 443 | `203.0.113.20` / `entry.example.com` | Iran → WaterWall :8443 |
| `in-53` | VLESS REALITY xhttp | 53 | `203.0.113.20` | Iran → WaterWall :8553 |
| `in-trojan-8444` | Trojan TLS | 8444 | `203.0.113.11` (direct exit) | crisis / no Iran WW yet |
| `in-ss2022` | Shadowsocks 2022 | 40000 | `203.0.113.11` (direct exit) | crisis / no Iran WW yet |

TLS for Trojan: cert files under `/var/lib/pg-node/certs/` on **both** NL node and panel docker (API validation).

## Web panels (Caddy on DE)

| Path | Backend | Tunnel |
|------|---------|--------|
| `/settle` `/pay` | DE loopback | — |
| `/mysub` | `sub.example.com` → rootit | — |
| `/sub/*` on `sub.*` | PasarGuard | — |
| `/ig` `/watch` | NL loopback | autossh reverse → DE |
| `/path` | IR loopback | autossh reverse → DE |

Production tunnels use **SSH key** `root/.ssh/shahrah_tunnel_de` (no `sshpass`). Units: `deploy/systemd/shahrah-*-tunnel.service`.

## Secrets

- `/root/.vpn-secrets/.env` on each host (0600): panel API keys, brain key.
- Rotate operator passwords and API keys after migration.

## Operator checks

```bash
# NL
systemctl is-active pg-node-service shahrah-waterwall
test -f /etc/shahrah/pg-node-active
ss -ltnp 'sport = :443'

# Panel
curl -sS -H "X-Api-Key: ..." https://panel.example.com/api/nodes | jq '.nodes[].status'

# Iran
systemctl is-active shahrah-waterwall shahrah-brain
shahrah backhaul status
```