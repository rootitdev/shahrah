# Domain handoff (blocks public CA + real CDN)

Lab tunnels work without a domain. These production pieces do **not**:

| Need | Why |
| --- | --- |
| Public HTTPS for PasarGuard + customer subscription URLs | Ready-made clients reject self-signed panel certs |
| Real CDN edge in front of `cdn-xhttp` | Hide origin IP; survive IP burns |
| Payment provider in front of `settle-hook` | Needs a public HTTPS callback URL |

## What to send the operator (no secrets in git)

1. **Edge hostname** for CDN clients — e.g. `edge.yourdomain.com`
2. **Panel hostname** — e.g. `panel.yourdomain.com`
3. Optional **subscription hostname** — e.g. `sub.yourdomain.com`
4. Confirm the DNS registrar / Cloudflare account is ready (API token optional; manual DNS is fine)

Do **not** paste Cloudflare API tokens or origin IPs into the public repo or chat if you can avoid it; prefer a private channel after the domain exists.

## One-shot on the exit (after DNS is yours)

```bash
# dry-run: prints DNS checklist + writes /etc/caddy/Caddyfile.shahrah
sudo ./deploy/attach-domain.sh \
  --edge edge.example.com \
  --panel panel.example.com \
  --sub sub.example.com

# when DNS points here:
sudo ./deploy/attach-domain.sh \
  --edge edge.example.com \
  --panel panel.example.com \
  --sub sub.example.com \
  --apply
```

Then install/reload Caddy with that Caddyfile, run `shahrah panel provision --update-core`,
and smoke from Iran. Details: [CDN.md](CDN.md), [PANEL.md](PANEL.md), [OPERATOR.md](OPERATOR.md).
