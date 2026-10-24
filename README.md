# Shahrah

A resilient anti-censorship VPN platform built on [Xray-core](https://github.com/XTLS/Xray-core).
Goal: stable access to social media, messengers and AI services for thousands of users in
heavily filtered networks, with servers that are hard to find and easy to install.

> **Status: early development.** Control-plane core, real tunnel prober, node installer,
> PasarGuard integration and the brain loop exist and are unit/loopback tested. **Nothing has
> been run on real servers yet** (installer, real-network behaviour, 1000+ user load). See
> [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/PANEL.md](docs/PANEL.md).

## Install a node

Debian 12+ or Ubuntu 24.04+ (Python >= 3.11), as root:

```bash
git clone <this repository> shahrah && cd shahrah
sudo ./deploy/install.sh --host vpn.example.org --target www.cloudflare.com

# resilient variant: 443 (Vision) + 80 and 53 (XHTTP), the TCP ports that survive allowlist shutdowns
sudo ./deploy/install.sh --host vpn.example.org --target www.cloudflare.com --multi-port
```

The installer downloads a **pinned, checksum-verified** Xray, generates the REALITY keys on the
machine, installs a hardened systemd service, enables BBR and opens only SSH and the VPN port in
`ufw`. It prints a `vless://` link for a first user that any ready-made client (v2rayNG,
Hiddify, Streisand, v2rayN, ...) can import. Re-running it upgrades the software and keeps the
existing keys and users.

Day-to-day:

```bash
shahrah user add alice
shahrah apply --xray-bin /usr/local/bin/xray --config-out /etc/shahrah/xray.json --group shahrah
systemctl restart shahrah-xray
shahrah link alice        # vless:// link
shahrah sub alice         # base64 subscription body
```

## What exists today

| Module | Purpose |
|---|---|
| `shahrah.models` | Validated models for servers, users and client endpoints. Refuses unsafe defaults (non-443 ports, IP REALITY targets, Apple/iCloud targets). |
| `shahrah.xray_config` | Renders an Xray server config: VLESS + REALITY with XTLS-Vision (raw) or XHTTP, no access log, private-range and BitTorrent blocking, loopback-only stats API. |
| `shahrah.links` | Builds `vless://` links and base64 subscription bodies that ready-made clients import. |
| `shahrah.oracle` | Pure path-health decision engine: fail/recover streaks, minimum dwell time, outage and allowlist-style (`restricted`) detection. |
| `shahrah.prober`, `shahrah.xray_client` | Real tunnel prober: one Xray client process, a SOCKS port per endpoint, an actual HTTPS request through each tunnel (not just a TLS check of the edge). Its output feeds the oracle. |
| `shahrah.keys`, `shahrah.state` | Pure-Python X25519 (RFC 7748) key generation and the atomic, owner-only node state file. |
| `shahrah.panel`, `shahrah.roles` | PasarGuard integration: reorder/disable panel hosts from the oracle ranking (fail-open when nothing is healthy), least-privilege role presets validated against the panel's real models. |
| `shahrah.brain` | The loop: probe -> oracle -> panel, tolerant of prober and panel failures. Run with `shahrah brain --config brain.json`. |
| `shahrah.deploy`, `shahrah.cli` | systemd unit, firewall plan and sysctl generators; the `shahrah` command. |

Rendered configs are verified against a **real Xray binary** (`xray run -test`), and the prober
has an end-to-end test that runs a real Xray server and client on loopback.

## Development

Requires Python 3.11+ and has no runtime dependencies.

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
ruff check . && ruff format --check .
pytest                                          # set XRAY_BIN to also run the Xray-backed tests
```

Without an Xray binary the Xray-backed tests are skipped, everything else still runs. The
end-to-end test (`-m e2e`) additionally needs internet access.

## Principles

- No hardcoded hosts, IPs, domains or secrets anywhere in the repository.
- The server never logs which sites users visit.
- Pure logic is separated from I/O so behaviour is unit-testable.

## License

Apache-2.0, see [LICENSE](LICENSE). PasarGuard (AGPL-3.0) is used only through its REST API and is not bundled or linked.

