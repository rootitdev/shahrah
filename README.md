# Shahrah

A resilient anti-censorship VPN platform built on [Xray-core](https://github.com/XTLS/Xray-core).
Goal: stable access to social media, messengers and AI services for thousands of users in
heavily filtered networks, with servers that are hard to find and easy to install.

> **Status: early development.** This repository currently contains the tested control-plane
> core. The one-command installer, the management panel integration and the health prober are
> not written yet (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the plan).

## What exists today

| Module | Purpose |
|---|---|
| `shahrah.models` | Validated models for servers, users and client endpoints. Refuses unsafe defaults (non-443 ports, IP REALITY targets, Apple/iCloud targets). |
| `shahrah.xray_config` | Renders an Xray server config: VLESS + REALITY with XTLS-Vision (raw) or XHTTP, no access log, private-range and BitTorrent blocking, loopback-only stats API. |
| `shahrah.links` | Builds `vless://` links and base64 subscription bodies that ready-made clients import. |
| `shahrah.oracle` | Pure path-health decision engine: fail/recover streaks, minimum dwell time, outage and allowlist-style (`restricted`) detection. |

Rendered configs are verified against a **real Xray binary** (`xray run -test`) in the test suite.

## Development

Requires Python 3.11+ and has no runtime dependencies.

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
ruff check . && ruff format --check .
pytest                                          # set XRAY_BIN to also validate configs with Xray
```

Without an Xray binary the Xray-validation tests are skipped, everything else still runs.

## Principles

- No hardcoded hosts, IPs, domains or secrets anywhere in the repository.
- The server never logs which sites users visit.
- Pure logic is separated from I/O so behaviour is unit-testable.
