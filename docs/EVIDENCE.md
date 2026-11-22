# Requirement evidence (living)

This file tracks what has been **proven** vs what still blocks goal completion.
It is not a claim that the objective is done.

| Requirement | Evidence | Status |
| --- | --- | --- |
| Xray REALITY+XHTTP on 443/80/53 | Lab exit listeners; installer `--multi-port` | Proven (lab) |
| Brain health / failover | Iran `brain --once`; panel disables filtered 53 | Proven (lab) |
| Burn / rotation machinery | `burn`, control-report file + `--on-burn` lab on Iran; `publish-control.example.sh` | Proven (lab wiring); no false burn when control says OK |
| Ready-client subscriptions | `serve-sub`; live sub **3× vless** `ready-check` PASS (443 Vision + 80/53 XHTTP) | Proven (lab); device TUN import still operator |
| No DNS/IPv6/WebRTC leak (template) | `client_template` + `shahrah leakcheck` PASS + Xray `-test` | Proven (template/static); **device TUN leak test still required** |
| No dead connections | `load-test` idle reap; Tuning keepalive | Proven (loopback) |
| Social / AI focus | Iran `probe`: IG, Telegram, ChatGPT, Claude | Proven (lab path) |
| Hard-to-burn / CDN profile | `cdn-xhttp` + TCP edge stand-in e2e + `attach-domain.sh` | Profile + attach playbook ready; **real edge needs domain** |
| Management (root/sales/customer) | PasarGuard: brain + **sales** roles on Iran; settle HMAC +1 day credit | Proven (lab); **public CA + real pay provider need domain** |
| Stable 1000–3000 users | Exit **2000**-conn; Iran wave **3000/3000**; soak 180 s **3849/3849**; soak 1800 s **23734/23745** (99.95%); 2 h soak mid-run ~99.95% | **30 min proven**; 2 h in progress; public CDN/CA still open |
| Simple install / GitHub-ready | `install.sh`, CI, hygiene, Apache-2.0, no secrets | Proven (repo) |
| Dedicated leak-proof client | — | **Deferred** (ready-made first) |

## How to extend evidence

```bash
# On Iran vantage (lab measured 3000/3000 generate_204 through REALITY):
ulimit -n 1048576
shahrah probe --config /var/lib/shahrah/brain.json --endpoint exit-443 --wave 3000 --json

# On foreign exit (lab measured 2000/2000 loopback tunnels):
ulimit -n 1048576
shahrah load-test --connections 2000 --json

# Sustained social/AI soak:
ulimit -n 1048576
shahrah soak --config /var/lib/shahrah/brain.json --endpoint exit-443 \
  --workers 80 --duration 1800 --interval 4 --progress-file /var/lib/shahrah/soak.progress.json --json
```

### Lab numbers (this deployment)

| Test | Result |
| --- | --- |
| Foreign `load-test --connections 2000 --skip-reap` | 2000/2000 ok |
| Iran `probe --wave 1000` via exit-443 | 1000/1000 ok, p95≈547 ms |
| Iran `probe --wave 2000` via exit-443 | 2000/2000 ok, p95≈794 ms |
| Iran `probe --wave 3000` via exit-443 | 3000/3000 ok, p95≈554 ms |
| Iran `soak` 80 workers, 180 s, social+AI | **3849/3849** ok, p50≈513 ms, p95≈2541 ms |
| Iran `soak` 60 workers, 1800 s, social+AI | **23734/23745** ok (99.95%), p50≈441 ms, p95≈692 ms, xray_died=false; 11 fails = telegram.org HTTP 404 |
| Iran `soak` 80 workers, 7200 s | **in progress** (started after 30 min run) |
| `shahrah leakcheck` (built-in template) | PASS |

Waves are concurrent short HTTPS fetches. Soaks keep one REALITY client up and repeatedly hit
Instagram / Telegram / ChatGPT / Claude / gstatic. Lab boxes are 2 GiB — functional path is
proven; production 1000–3000 *heavy* sessions still wants larger exits + public CDN/CA.
