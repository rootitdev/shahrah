# vpn-infra-kit remediation (audit items 2, 5, 6)

Apply to your **local** `vpn-infra-kit` checkout (private repo). This directory ships with **shahrah**; it is not a second git repository.

## Quick apply

```bash
python3 contrib/vpn-infra-kit-remediation/remediate_kit.py /path/to/vpn-infra-kit
for f in install.sh rollback.sh installer/lib.sh; do bash -n "/path/to/vpn-infra-kit/$f" || exit 1; done
```

What it does:

1. Converts every `*.sh` to LF and adds `.gitattributes` (item **2**).
2. Pins Xray to `v26.10.21` with SHA-256 verification (same as `deploy/install.sh` in shahrah) (item **5**).
3. Removes `curl | sh` for acme.sh and Iran-side Xray-install — installer must copy binaries from Exit instead (item **5**).
4. Sets XHTTP `mode` to `packet-up` in templates **and** `scripts/render_*_configs.py`.
5. Removes `curl|sh` from install, Iran bootstrap (xray/hy2 must be copied or pinned manually).
6. Guards kit vs shahrah-brain in `phase_preflight` when `SHAHRAH_BRAIN_ACTIVE=1`.

After apply, run `./install.sh --plan` on a control host with a filled `.env` (still no production install required for validation).

## Verify loopback XHTTP (item 6)

On a machine with `xray` and shahrah installed:

```bash
pytest tests/test_kit_xhttp_reference.py -q
pytest tests/test_cdn.py::test_real_xray_accepts_server_and_client_configs -q
```

Shahrah CDN XHTTP loopback is the reference shape; kit templates should match `packet-up`, not `auto`.
