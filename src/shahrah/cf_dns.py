"""Cloudflare DNS helper (scoped token in /root/.vpn-secrets/.env). Stdlib only."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_ENV = Path("/root/.vpn-secrets/.env")


def load_env(path: Path | None = None) -> dict[str, str]:
    env_path = path or Path(os.environ.get("CF_DNS_ENV", str(DEFAULT_ENV)))
    if not env_path.is_file():
        raise SystemExit(f"missing env file: {env_path} (need CF_API_TOKEN=)")
    env: dict[str, str] = {}
    for ln in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = ln.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def cf_request(method: str, url: str, token: str, body: object | None = None) -> dict:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "shahrah-cf-dns/1.0")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")[:800]
        raise SystemExit(f"CF_HTTP {exc.code} {url} {raw}") from exc


def main(argv: list[str] | None = None) -> None:
    args = argv if argv is not None else sys.argv[1:]
    env = load_env()
    token = env.get("CF_API_TOKEN") or env.get("CF_DNS_TOKEN") or ""
    if not token:
        raise SystemExit("CF_API_TOKEN or CF_DNS_TOKEN missing in secrets env")
    cmd = args[0] if args else "help"
    if cmd == "zones":
        data = cf_request("GET", "https://api.cloudflare.com/client/v4/zones?per_page=50", token)
        for z in data.get("result") or []:
            print(z["name"], z["id"], z["status"])
        return
    if cmd == "list":
        if len(args) < 2:
            raise SystemExit("usage: list ZONE_ID")
        zone_id = args[1]
        data = cf_request(
            "GET",
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?per_page=100",
            token,
        )
        for rec in data.get("result") or []:
            print(
                rec["type"],
                rec["name"],
                rec["content"],
                "proxied=" + str(rec["proxied"]),
                rec["id"],
            )
        return
    if cmd == "upsert":
        if len(args) < 5:
            raise SystemExit("usage: upsert NAME CONTENT PROXIED ZONE_ID")
        name, content, proxied, zone_id = args[1:5]
        proxied_b = proxied.lower() in ("1", "true", "yes", "orange")
        existing = cf_request(
            "GET",
            "https://api.cloudflare.com/client/v4/zones/"
            + zone_id
            + "/dns_records?type=A&name="
            + urllib.parse.quote(name),
            token,
        )
        payload = {
            "type": "A",
            "name": name,
            "content": content,
            "ttl": 1 if proxied_b else 120,
            "proxied": proxied_b,
        }
        recs = existing.get("result") or []
        if recs:
            rid = recs[0]["id"]
            data = cf_request(
                "PUT",
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}",
                token,
                payload,
            )
            print("UPDATED", name, data.get("success"), "proxied", proxied_b)
        else:
            data = cf_request(
                "POST",
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
                token,
                payload,
            )
            print("CREATED", name, data.get("success"), "proxied", proxied_b)
        return
    if cmd == "setting":
        if len(args) < 4:
            raise SystemExit("usage: setting ZONE_ID KEY VALUE")
        zone_id, key, value = args[1], args[2], args[3]
        data = cf_request(
            "PATCH",
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/{key}",
            token,
            {"value": value},
        )
        print("SETTING", key, data.get("success"), data.get("errors"))
        return
    print("usage: shahrah cf-dns zones|list ZONE_ID|upsert NAME IP PROXIED ZONE_ID|setting ZONE KEY VAL")
    raise SystemExit(2)


if __name__ == "__main__":
    main()