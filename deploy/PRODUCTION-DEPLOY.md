# Production control plane (main branch) — ops worker

**Sources of truth:** `github.com/rootitdev/shahrah` **main** only.  
**Targets (owner):** Netherlands exit `185.19.33.221`, Iran relay `87.107.110.162`.  
**Domain (parent + Cloudflare):** `bluelark.ir` — DNS/TLS changes are **parent** only (not automated here).

## Role separation

| Host | Role | User/UUID source | Xray on :443 |
|------|------|------------------|--------------|
| **Netherlands** | PasarGuard panel + Shahrah **provisioned core** | **PasarGuard only** | **One** Xray process owned by the panel node/core (not a second `shahrah-xray` binding) |
| **Iran** | WaterWall relay entry | Clients use **NL** subscription users (PG) | No public REALITY exit on Iran for customers |

Shahrah on the exit: generate REALITY **infrastructure** (keys, listeners template) via `shahrah panel provision`; **do not** manage customer UUIDs in `state.json` in production (`SHAHRAH_SKIP_FIRST_USER=1`). Brain (optional) uses API key with `brain_role` only.

PasarGuard install: use the **official** upstream release/install path from [PasarGuard/panel](https://github.com/PasarGuard/panel) (pinned tag recorded in ops vault). This repo does **not** vendor PasarGuard; it speaks **REST** (`docs/PANEL.md`).

## DNS / ports (parent)

| Name | Type | Points to | Purpose |
|------|------|-----------|---------|
| `reality.bluelark.ir` (example) | A/AAAA | NL `185.19.33.221` | REALITY client SNI/host |
| `panel.bluelark.ir` (example) | A or CNAME via CF | NL | PasarGuard UI + API `https://panel...:443` or `:8000` |
| Iran IP | A | `87.107.110.162` | Relay front; subscription links use `client-host` / multi-exit ports per `docs/beta/BETA-OPS-RUNBOOK-fa.md` |

**Blocked until parent:** public CA cert for panel subscription URLs, exact subdomain names, Cloudflare proxy mode for REALITY (usually DNS-only on exit IP).

## Netherlands — ordered steps

```bash
git clone https://github.com/rootitdev/shahrah.git /opt/shahrah && cd /opt/shahrah && git checkout main
# 1) PasarGuard (official installer) — store owner API key in /root/.vpn-secrets/ (0600), not in git
# 2) Shahrah CLI/bootstrap:
export SHAHRAH_SKIP_FIRST_USER=1
sudo ./deploy/install.sh --host reality.bluelark.ir --target www.cloudflare.com
# If stale CLI after git pull: same command re-syncs venv (see docs/OPERATOR.md)
# 3) Panel provision (owner API key in env):
export SHAHRAH_PANEL_URL=https://panel.bluelark.ir:8000
export SHAHRAH_PANEL_API_KEY=<from vault file>
shahrah panel bootstrap --probe-group-id <id>
shahrah panel provision --core-name shahrah-nl --state /etc/shahrah/state.json
# Do NOT enable independent shahrah-xray on 443 if panel node already binds it — disable duplicate unit first
```

Backhaul key: `germany-attach-waterwall.sh` / `exit-attach-relay-peer.sh` patterns; copy `backhaul*.key` to Iran out-of-band.

## Iran — relay

```bash
git clone ... /opt/shahrah && git checkout main
sudo EXIT_PEER_IP=<NL_PUBLIC_IP> ./deploy/beta/iran-relay-install.sh
# multi-exit later: iran-bootstrap-relay-peer.sh (see beta runbook)
```

## Credentials

- Panel owner + brain API keys: root-readable files under `/root/.vpn-secrets/` or `/etc/shahrah/*.env` (0640), never argv, never CI artifacts.
- REALITY private key: `/etc/shahrah/state.json` on NL; backup via `scripts/backup-shahrah-bundle.sh` (+ panel DB per PasarGuard docs).

## Lifecycle / status (no bootstrap side effects)

```bash
sudo ./deploy/shahrah-wizard.sh          # status menu uses read-only CLI
sudo ./deploy/uninstall-shahrah.sh --dry-run
shahrah lifecycle status --fa --src-root /opt/shahrah
```

Bootstrap (mutating) only: `sudo ./deploy/install.sh ...`

## Limitations

- Multi-exit WaterWall: config/render tested; multi-instance binary e2e not claimed on live hosts.
- Panel DB backup/restore: follow PasarGuard upstream; Shahrah bundle covers `/etc/shahrah` only.
- Reboot / full Internet e2e: not asserted by this repo's CI.
