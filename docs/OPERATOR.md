# Operator runbook

Pick **one** control plane: [CONTROL-PLANE.md](CONTROL-PLANE.md) (Shahrah brain *or* vpn-infra-kit failover, not both).

End-to-end path to a lab or production Shahrah deployment. No real IPs/domains belong in git;
substitute your own.

## 1. Foreign exit (REALITY multi-port)

```bash
git clone <this-repo> shahrah && cd shahrah
sudo ./deploy/install.sh --host YOUR.EXIT.HOST --target www.cloudflare.com --multi-port
```

Optional CDN origin (needs a real edge hostname — see [CDN.md](CDN.md)):

```bash
shahrah listener add 8080:cdn-xhttp:edge.example.com
shahrah apply --xray-bin /usr/local/bin/xray --config-out /etc/shahrah/xray.json --group shahrah
systemctl restart shahrah-xray
```

Capacity check on the exit:

```bash
shahrah capacity --users 2000
ulimit -n 1048576
shahrah load-test --connections 1000 --json
```

Subscription for ready-made clients (secret never on argv):

```bash
umask 077
printf 'SHAHRAH_SUB_SECRET=%s\n' "$(shahrah serve-sub --print-secret)" > /etc/shahrah/sub.env
shahrah print serve-sub-unit > /etc/systemd/system/shahrah-serve-sub.service
systemctl enable --now shahrah-serve-sub
# SSH tunnel from operator laptop: ssh -L 8788:127.0.0.1:8788 root@exit
```

## 2. Iran brain + PasarGuard

```bash
sudo ./deploy/install.sh --role brain
# install PasarGuard separately; then:
export SHAHRAH_PANEL_URL=https://127.0.0.1:8000   # must be https if the panel serves TLS
export SHAHRAH_PANEL_API_KEY=…
export SHAHRAH_PANEL_INSECURE_TLS=1   # lab self-signed only (plain http:// causes RemoteDisconnected)
shahrah panel provision --update-core
shahrah panel bootstrap --probe-group-id …
shahrah panel client-template --update
# paste brain_remarks into /var/lib/shahrah/brain.json (or /etc/shahrah/brain.json)
systemctl restart shahrah-brain
```

Iran-path smoke (social + AI):

```bash
shahrah probe --config /var/lib/shahrah/brain.json --endpoint exit-443 --wave 100 --json
```

Burn detection: publish a control report from a free network
(`shahrah brain --write-report /path/report.json`) and point the field brain at it with
`--control-report`. On burn, run an operator script (`deploy/on-burn.example.sh`).

## 3. Ops console (unified shell)

```bash
TOKEN=$(shahrah ops --print-token)
shahrah ops --token "$TOKEN" \
  --stats-server 127.0.0.1:10085 \
  --access-log /var/log/shahrah/access.log \
  --ig-mult-config /var/lib/shahrah/ig-mult.json
```

Optional kit HTML panels (`/ig/`, `/settle/`, `/watch/`) — separate from `ops`; see [PANELS.md](PANELS.md):

```bash
sudo PANEL_BASE=https://panel.example.com:2096 ./deploy/install-panels.sh
```

## 4. Still needs your domain / hardware

| Gap | Blocker |
| --- | --- |
| Public CA panel + customer HTTPS subs | Domain + Let's Encrypt |
| Real CDN edge | Domain pointed at Cloudflare (or similar) |
| 1000–3000 Iranian-path users | Larger exit RAM/CPU than a 2 GiB lab box |
| Dedicated leak-proof client | After ready-made clients are stable |

Handoff checklist and `attach-domain.sh`: [DOMAIN.md](DOMAIN.md).

## 5. Ready-client leak checklist (before dedicated app)

1. Publish the panel client template (`shahrah panel client-template --update`).
2. Static gate: `shahrah leakcheck --json` must PASS (DoH-only DNS, IPv6/STUN/multicast blocks,
   loopback SOCKS/HTTP).
3. Validate the subscription blob before sharing:
   `shahrah --state /var/lib/shahrah/state.json sub USER | shahrah ready-check`
4. On Android/iOS/Windows: import the subscription, enable **TUN/VPN mode** (not proxy-only),
   then visit a WebRTC leak site and an IPv6 echo while connected. Proxy mode alone cannot
   block browser WebRTC.
5. Keep Instagram / Telegram / ChatGPT smoke via `shahrah probe` from the Iran vantage.

Burn control vantage (free network): see `deploy/publish-control.example.sh` and point the
field brain at that report with `--control-report` / `SHAHRAH_CONTROL_REPORT`.

## Evidence already collected in lab

* Exit loopback: 1000 concurrent REALITY tunnels + idle reap at 300
* Iran→foreign: Instagram, Telegram, ChatGPT, Claude, gstatic through 443/80
* Iran-path concurrent HTTPS wave **3000/3000** on exit-443 (plus social/AI smoke)
* Iran soak 30 min social/AI: **23734/23745** (99.95%), xray stayed up
* `shahrah leakcheck` PASS on the published client template
* Live exit subscription: `ready-check` PASS (3 REALITY links)
* Burn: Iran brain `--control-report` + `--on-burn` (no false burn when control OK)
* CDN profile proven through a TCP edge stand-in (clients never dial origin port)
* Brain disables filtered TCP/53 in the panel while keeping the listener;
  `SHAHRAH_CONTROL_REPORT` / `SHAHRAH_ON_BURN` / `SHAHRAH_WRITE_REPORT` load from `brain.env`
