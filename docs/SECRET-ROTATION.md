# Secret rotation after an audit zip (item 1)

If your working tree ever contained `shahrah/_lt/` (keys, panel API material, REALITY
material), treat those values as **compromised for any environment that received them**,
even though `_lt/` is gitignored and excluded from routine hygiene scans.

## On live servers (operator — not done by this repo)

1. Rotate REALITY keys: new `shahrah init` on a fresh state file or panel-provisioned core;
   re-issue client links.
2. Revoke and replace PasarGuard API keys (`brain`, `settle`, `PANEL_API_KEY`).
3. Rotate `SHAHRAH_SUB_SECRET`, `SHAHRAH_OPS_TOKEN`, settle-web session secrets, and any
   Telegram backup GPG passphrases (`BACKUP_GPG_PASS` per host).
4. Remove archived zip copies that contain `_lt/` from laptops, tickets, and object storage.
5. Never paste new secrets into chat; use `EnvironmentFile=` units with mode `600`.

## In git / archives

- Keep `_lt/` out of commits (`_lt/` is in `.gitignore`).
- Before sharing a zip for audit, delete `_lt/` and any `*.env` / `*creds*` / `*api_key*`
  files (the audit packager should mirror that policy).

## Verification

```bash
test ! -d _lt || test -z "$(find _lt -type f ! -name '*.md' ! -name '*.sh' 2>/dev/null | head -1)" \
  || echo "WARNING: _lt contains non-doc files — purge before publish"
pytest tests/test_hygiene.py -q
```
