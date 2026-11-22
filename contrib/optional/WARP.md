# WARP (removed from supported install path)

Cloudflare WARP egress (`wgcf` + WireGuard) was optional Google-family routing. It is **no longer** installed by `deploy/install.sh` and the `shahrah warp` CLI command was removed.

- **Legacy nodes:** `state.json` may still contain a `warp` block; `shahrah apply` keeps rendering it for backward compatibility.
- **Module:** `src/shahrah/warp.py` remains for that compatibility (and Hy2 `bindDevice` if you still have old state).
- **New deployments:** do not enable WARP; use direct exit egress.

To strip WARP from an old node: edit `state.json` and remove the `warp` key, then `shahrah apply` and restart Xray.