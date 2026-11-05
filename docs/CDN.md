# CDN-fronted XHTTP (operator guide)

Shahrah can expose a secondary listener as plain XHTTP behind a CDN (`cdn-xhttp`). The
origin never terminates public TLS for that path; the CDN edge does. REALITY on 443/80/53
stays the crisis path; CDN is the *hard-to-burn* front when the origin IP must stay hidden.

## What the code already does

* Listener profile `cdn-xhttp` with unguessable path and `packet-up` mode (CDN-safe).
* Client links and panel host payloads point at the **CDN hostname**, not the origin IP.
* Loopback e2e (`tests/test_cdn.py`) validates render + `xray run -test`.
* Tunnel e2e through a TCP edge stand-in (`tests/test_prober.py::test_cdn_tunnel_works_through_a_tcp_edge_proxy`)
  so clients never dial the origin port directly.

What is **not** proven until you attach a real edge: Iran→CDN→origin latency, WAF rules that
do not break XHTTP, and certificate coverage for the customer hostname.

For a Caddy + Let's Encrypt edge on your own hostnames, see
[`deploy/Caddyfile.example`](../deploy/Caddyfile.example).
When you have real DNS, run [`deploy/attach-domain.sh`](../deploy/attach-domain.sh)
(checklist: [DOMAIN.md](DOMAIN.md)).

## Minimal Cloudflare setup (example)

1. Buy/point a hostname (e.g. `edge.example.com`) at Cloudflare; orange-cloud the A/AAAA to the
   foreign exit (or a grey-cloud intermediate that only Cloudflare can hit).
2. On the exit, add a CDN listener (path must stay secret):

   ```bash
   shahrah listener add 8080:cdn-xhttp:edge.example.com:/<long-unguessable-path>
   shahrah apply --xray-bin /usr/local/bin/xray --config-out /etc/shahrah/xray.json --group shahrah
   systemctl restart shahrah-xray
   ufw allow 8080/tcp   # only if the CDN hits the origin directly on 8080
   ```

3. Cloudflare SSL/TLS mode: **Full** (origin can present any cert on 8080 if you terminate TLS
   yourself) or keep origin plain HTTP on a high port and use **Flexible** only for lab — Full
   is preferred once the origin has a real cert on the CDN listener.
4. Disable Rocket Loader / email obfuscation / HTML rewriting for that hostname; they corrupt
   binary XHTTP.
5. Re-provision panel hosts so subscriptions advertise the CDN hostname:

   ```bash
   shahrah panel provision --update-core
   ```

6. From an Iranian vantage, import the subscription and confirm the CDN host is reachable while
   the origin IP is not probed from the client.

## Safety

* Never commit the real CDN hostname or origin IP to git.
* Rotate the XHTTP path if the URL leaks; treat it like a credential.
* Keep REALITY multi-port as fallback when the CDN product/WAF breaks the tunnel.

## Port 80 REALITY+XHTTP (not recommended)

Field finding (EXIT xray 26.10.21): a `reality-xhttp` listener on TCP 80 fails even on
loopback (client dials, tunnel never carries data). Prefer:

* `reality-vision` on 443
* `cdn-xhttp` behind Cloudflare (plain origin + edge TLS)
* WaterWall relay

Do not ship port-80 REALITY+XHTTP as a default crisis path until upstream XHTTP+REALITY on
non-443 is proven. ``install.sh --multi-port`` therefore adds only ``53:reality-xhttp``
(not 80).

## Port 80 / CF HTTP family (2052, 8080, 8880)

REALITY must not listen on TCP 80. The CDN origin speaks **plain XHTTP** on an internal
port (default ``8080``, ufw-deny from the world). Caddy (or another reverse proxy) publishes:

* ``:2053`` HTTPS to Cloudflare (client TLS to the edge)
* ``:2052`` HTTP to Cloudflare (CF Flexible / HTTP origins)

Both ``2052`` and ``2053`` must be firewalled to **Cloudflare IP ranges only**
(``install.sh`` / ``shahrah-cf-allowlist``). Direct hits from Iran on those ports should time out.

Xray 26+ clients refuse VLESS with ``security=none`` toward a public edge; phone apps that
use sing-box may still import an HTTP ``:2052`` / ``:80`` link. Prefer the TLS ``:2053`` link
for Xray-core clients.

