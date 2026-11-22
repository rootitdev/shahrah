# Capacity (1 000–3 000 users)

Shahrah targets social / messenger / AI traffic on one REALITY exit, not gaming UDP.

```bash
shahrah capacity --users 2000
shahrah capacity --users 2000 --json
shahrah load-test --connections 500 --json          # loopback REALITY wave + idle reap
shahrah load-test --connections 1000 --skip-reap    # faster smoke on a larger box
```

The plan shrinks per-connection buffers as concurrency grows and estimates Xray RSS plus a
recommended VPS RAM floor. Apply kernel tuning from the installer:

```bash
shahrah print sysctl > /etc/sysctl.d/99-shahrah.conf
sysctl --system
```

Local / exit evidence (`shahrah load-test` or `pytest -m load`, needs `xray` + internet for
the REALITY cover handshake): concurrent tunnels on loopback, idle reaping within
`conn_idle_s`, no half-open leftovers. Run the CLI **on the foreign exit** to size that
kernel/RAM; raise `ulimit -n` (the harness also lifts `RLIMIT_NOFILE`). Lab result on a
2 GiB exit: **2000/2000** concurrent tunnels ok (skip-reap) and **300/300** with idle
reaping. Iran vantage measured **3000/3000** concurrent short HTTPS fetches through exit-443.
That is strong concurrency evidence. Lab also ran a **30 min** Iran-path social/AI soak at
**99.95%** success (60 workers) and a **2 h** soak in progress — still not a substitute for
production-scale heavy sessions or a real CDN edge. Size with `capacity` and re-check after
attaching public TLS/CDN.

Dead connections are fought with `Tuning.conn_idle_s`, TCP keepalive, and IPv4-only outbound
resolution so AAAA-only dead ends do not accumulate.
