# path-web

UI for `shahrah backhaul` — manual path pick and auto/manual mode. Install on **Iran relay** or **exit** (where WaterWall runs).

```bash
sudo PANEL_BASE=https://panel.example.com:2096 LISTEN=127.0.0.1:8791 bash install.sh
```

Requires `shahrah backhaul init` and optional `shahrah-backhaul-failover.timer` from `deploy/install.sh --with-waterwall`.