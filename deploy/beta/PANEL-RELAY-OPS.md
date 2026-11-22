# Panel-owned exit + Iran relay (ops runbook)

Use when **PasarGuard node** already listens on `127.0.0.1:443` (VLESS REALITY). Shahrah installs **WaterWall only** — no second Xray, no `state.json` user edits on attach.

Variables: `<NL_IPV4>` foreign exit, `<IRAN_IPV4>` Iran relay, optional `<WW_TUNNEL_PORT>` default `8443`, `<WW_MODE>` default `reverse`.

## Netherlands (after panel node is healthy)

```bash
cd /opt/shahrah && git fetch origin && git checkout main && git reset --hard <MERGED_SHA>
export SHAHRAH_SKIP_FIRST_USER=1   # only for full install.sh node path, not required for WaterWall attach
sudo IRAN_PEER_IP=<IRAN_IPV4> ./deploy/beta/panel-exit-attach-waterwall.sh
```

Verify:

```bash
systemctl is-active shahrah-waterwall
test -s /etc/shahrah/backhaul.key && ls -l /etc/shahrah/backhaul.key   # mode 600 root
! systemctl is-active shahrah-xray 2>/dev/null || echo "STOP: shahrah-xray must not own :443"
curl -sS -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:443/ || true   # panel node only
```

Rollback (exit):

```bash
sudo systemctl disable --now shahrah-waterwall
sudo rm -f /etc/systemd/system/shahrah-waterwall.service
sudo systemctl daemon-reload
# panel node untouched
```

Copy key (out-of-band):

```bash
scp /etc/shahrah/backhaul.key root@<IRAN_IPV4>:/etc/shahrah/backhaul.key
```

## Iran (partial install OK: venv, waterwall binary, 99-shahrah.conf)

```bash
cd /opt/shahrah && git fetch origin && git merge --ff-only origin/main   # no reset --hard
sudo SHAHRAH_WHEELHOUSE=/opt/wheelhouse WW_CPU_VARIANT=old-cpu EXIT_PEER_IP=<NL_IPV4> \
  ./deploy/beta/iran-relay-install.sh
```

On Xeon without AVX2, `auto` selects the official `*-gcc-x64-old-cpu` zip (zip checksum verified
on download). Re-runs skip download only when `/etc/shahrah/waterwall-cpu.variant` matches and the
installed ELF matches the pinned **binary** digest (not the zip).

Re-run is idempotent (re-downloads WaterWall if needed, restarts unit).

Verify:

```bash
systemctl is-active shahrah-waterwall
ss -ltnp 'sport = :443'    # Iran front listener
```

Iran firewall (if ufw was skipped at install):

```bash
sudo ufw allow 443/tcp
sudo ufw allow from <NL_IPV4> to any port 8443 proto tcp
```

Rollback (Iran):

```bash
sudo systemctl disable --now shahrah-waterwall
```

## Interface keys / client URLs

Panel remains **sole** UUID/user owner. Subscription links and REALITY parameters stay in PasarGuard. Iran only adds domestic entry; clients still use panel-issued credentials pointing at the **NL** REALITY target (e.g. `www.cloudflare.com`), not Shahrah `state.json` on Iran.

## Limitations

CI covers serialization, script syntax, and mocked attach guards — not live NL↔Iran HTTP200/204 through WaterWall on real hosts.
