# Multi-path backhaul failover

Operator leg between **Iran relay** and **foreign exit** (WaterWall). This is separate from client REALITY paths (443/80/53) and from `shahrah brain` subscription failover.

## Paths (default priority)

| id | What it does |
|----|----------------|
| `waterwall-reverse` | Default: exit dials Iran (`--ww-mode reverse`) |
| `waterwall-direct` | Iran dials exit |
| `waterwall-alt` | Alternate tunnel port / cover SNI from store |
| `ssh-fallback` | `deploy/install-ssh-fallback.sh` autossh bridge (ops/smoke) |
| `paqet-client` | Crisis SOCKS sidecar — not a drop-in for :443 user relay |

Edit priority in `/etc/shahrah/backhaul-failover.json` if needed.

## CLI

```bash
shahrah backhaul init --side iran --iran-ip IR --exit-ip EXIT   # once
shahrah backhaul status --json
shahrah backhaul set waterwall-direct
shahrah backhaul auto
shahrah backhaul failover-once    # used by systemd timer
```

`install.sh --with-waterwall` writes the store, enables `shahrah-backhaul-failover.timer` (15s).

## Web UI

```bash
sudo PANEL_BASE=https://panel.example.com:2096 PANELS=path ./deploy/install-panels.sh
```

## SSH fallback as path 4

On Iran when reverse/direct are blocked:

```bash
export SSH_FALLBACK_PEER=EXIT_IP
./deploy/install-ssh-fallback.sh
```

Then include `ssh-fallback` in priority or let auto failover reach it.

## vs vpn-infra-kit

Kit uses Xray `put_selector` for CF/XHTTP/DIRECT bridges. Shahrah uses WaterWall re-render + systemd. Use **one** control plane per site ([CONTROL-PLANE.md](CONTROL-PLANE.md)).