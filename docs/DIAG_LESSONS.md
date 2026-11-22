# Lessons from the manual ops scripts

The `diag/` folder next to this repo holds ~100 one-off scripts written while running the
first Iran entry + foreign exit deployment by hand (PasarGuard panel, Xray cores, an nginx
"path-web" selector, CDN fronts). They are **not** part of the product and contain live
addresses and credentials, so nothing was copied from them. This page records the problems
that came up more than once and where the product now handles each one.

| # | Recurring problem (scripts that dealt with it) | Now handled by |
|---|---|---|
| 1 | REALITY handshake target unreachable or slow *from the Iran server itself*; operators kept probing candidate targets by hand and finally pointed REALITY at a local TLS server (`fix_reality_dest`, `fix_reality_local_dest*`, `reality_more`) | `shahrah node-check` → `reality-target` (TLS 1.3 from the node); `sni-scout` for picking targets |
| 2 | Certificate pin mismatch: SPKI (public key) hash used where Xray/Hysteria expect the leaf-certificate DER hash; both are 64 hex chars (`calc_pins`, `fix_tun1_pin`, `probe_direct_pin`) | `hysteria2.cert_pin()` computes the right hash from the PEM; `node-check --cert --pin` → `cert-pin` |
| 3 | Stray processes on public ports (old xray, nginx, a second panel core) made paths flap (`final_check`, `finish_hybrid`, `hybrid_exit_final`) | `install.sh` `free_public_ports`; `node-check` → `port-owners` |
| 4 | Ports "opened" in ufw but a separate nftables table (`inet vpn`) dropped them first (`finish_two_nodes`, `open_exit_node_port`, `verify_exit_45`) | `node-check` → `firewall` warns when ufw and another nft table coexist |
| 5 | Broken/poisoned recursive DNS on the Iran host; worry about being an open resolver (`fix_iran_dns_host`, `fix_health_import`) | Xray resolves over DoH (`Tuning.dns_servers`); `node-check` → `dns-exposure` (public :53 must be Xray, never a resolver) |
| 6 | CDN names with AAAA on hosts without working IPv6 → hangs until v6 timeout; scripts forced `curl -4` (`cf_v4v6`, `fix_tunnel`) | `nodecheck.ipv6_sanity`; WaterWall connectors use `prefer-ipv4` |
| 7 | Health checks with an odd User-Agent got 403/challenge pages from CDNs and marked good paths down (`finish_path_on_exit`, `_chk`) | prober sends a mobile-browser UA (`prober.PROBE_USER_AGENT`) |
| 8 | Backhaul port open to the world was found and probed (`direct_truth`, firewall notes: "only from the Iran IPs") | WaterWall tunnel listener whitelists the peer (`restrict_peer=True`); reverse mode exposes no port on the exit |
| 9 | Panel-managed cores dropped inbounds/certs on regeneration; operators ran a standalone Xray for the backhaul next to the panel core (`fix_exit_core_certs`, `fix_exit_pgnode_final`, `hybrid_exit_final`) | Backhaul is a separate data plane (WaterWall), independent of the panel; no panel on the Iran relay (`--role relay`) |
| 10 | Connection churn limits (somaxconn, fin_timeout, file limits) and PMTU black holes (`iran_sysctl`) | `shahrah print sysctl` (now with `tcp_mtu_probing=1`); `node-check` → `sysctl` |
| 11 | Instagram (Meta CDN) and Telegram behaved differently on the same path; checked separately, direct from exit vs through Iran (`meta_vs_tg`, `test_tun1_dual`) | social probe (`--social-probe`) weights Instagram endpoints; brain compares vantages (burn detection) |
| 12 | Secrets embedded in scripts (passwords in base64 blobs, UUIDs inline) (`_upload_and_deploy`, `_orch`) | product keeps secrets in 0600 files / EnvironmentFile; `tests/test_hygiene.py`; `.gitignore` excludes `*.pem`, `*.key`, state |

## Operator checklist (run on every new node)

```bash
shahrah node-check                       # target, ports, firewall, DNS, sysctl
shahrah sub first | shahrah ready-check --sni-dns   # links parse; SNI plausible for the IP
```

Still manual: measuring Instagram vs Telegram from a real Iranian vantage, and per-ASN
differences (see `tactics.py`; no real ASN data yet).
