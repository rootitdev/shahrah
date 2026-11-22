#!/usr/bin/env python3
"""Resolve sni-watch names → Xray email ids via PasarGuard HTTP API.

Runs on the **exit** host next to sni-watch (NL). No docker exec, no SSH to
Iran, no master sqlite — panel API is the system of record.

Writes:
  /etc/sni-watch/usermap.json       name/uuid/id → numeric id (Xray email)
  /etc/sni-watch/panel-status.json  id → {username,status}
and updates watchlist.aliases so access.log ``email: N`` matches username rows.
"""
from __future__ import annotations

import json
import os
import ssl
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MAP_PATH = Path(os.environ.get("SNI_WATCH_USERMAP", "/etc/sni-watch/usermap.json"))
STATUS_PATH = Path(
    os.environ.get("SNI_WATCH_PANEL_STATUS", "/etc/sni-watch/panel-status.json")
)
DB_PATH = Path(os.environ.get("SNI_WATCH_DB", "/var/lib/sni-watch/watch.db"))


def _creds() -> tuple[str, str]:
    base = (
        os.environ.get("SHAHRAH_PANEL_URL")
        or os.environ.get("PANEL_URL")
        or ""
    ).strip().rstrip("/")
    key = (
        os.environ.get("SHAHRAH_PANEL_API_KEY")
        or os.environ.get("PANEL_API_KEY")
        or ""
    ).strip()
    if base and key:
        return base, key
    for path in (
        Path("/root/.vpn-secrets/.env"),
        Path("/etc/sni-watch/panel.env"),
        Path("/etc/shahrah/ig-mult.env"),
    ):
        if not path.is_file():
            continue
        for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
            s = ln.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k in {"SHAHRAH_PANEL_URL", "PANEL_URL"} and not base:
                base = v.rstrip("/")
            if k in {"SHAHRAH_PANEL_API_KEY", "PANEL_API_KEY"} and not key:
                key = v
    if not base or not key:
        raise SystemExit(
            "need SHAHRAH_PANEL_URL + SHAHRAH_PANEL_API_KEY "
            "(env or /root/.vpn-secrets/.env)"
        )
    return base, key


def _api_get(path: str) -> dict | list:
    base, key = _creds()
    url = f"{base}{path}"
    req = urllib.request.Request(url, headers={"X-Api-Key": key}, method="GET")
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=45) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:200]
        raise SystemExit(f"panel API {e.code} {path}: {body}") from e
    except Exception as e:  # noqa: BLE001
        raise SystemExit(f"panel API unreachable ({base}): {e}") from e


def watch_queries() -> list[str]:
    if not DB_PATH.is_file():
        return []
    conn = sqlite3.connect(str(DB_PATH))
    try:
        rows = conn.execute(
            "SELECT email, label, aliases FROM watchlist"
        ).fetchall()
    finally:
        conn.close()
    seen: set[str] = set()
    out: list[str] = []
    for email, label, aliases in rows:
        for part in (email, label, *(a.strip() for a in (aliases or "").split(","))):
            s = str(part or "").strip()
            if not s or s.lower() in seen:
                continue
            seen.add(s.lower())
            out.append(s)
    return out


def _uuid_from_user(u: dict) -> str:
    for key in ("proxy_settings", "proxies"):
        raw = u.get(key)
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                raw = None
        if isinstance(raw, dict):
            vless = raw.get("vless")
            if isinstance(vless, dict) and vless.get("id"):
                return str(vless["id"]).strip()
            if raw.get("id") and key == "proxies":
                # some shapes nest protocol → {id: uuid}
                pass
            for proto in raw.values():
                if isinstance(proto, dict) and proto.get("id"):
                    return str(proto["id"]).strip()
    return ""


def fetch_users() -> list[dict]:
    out: list[dict] = []
    offset = 0
    while offset < 10000:
        page = _api_get(f"/api/users?offset={offset}&limit=100")
        users = page.get("users", page) if isinstance(page, dict) else page
        if not isinstance(users, list) or not users:
            break
        out.extend(u for u in users if isinstance(u, dict))
        if len(users) < 100:
            break
        offset += 100
    return out


def resolve(names: list[str]) -> tuple[dict[str, str], dict[str, dict]]:
    want = {n.strip().lower() for n in names if n.strip()}
    mapping: dict[str, str] = {}
    status: dict[str, dict] = {}
    if not want:
        return mapping, status

    for u in fetch_users():
        try:
            sid = str(int(u["id"]))
        except (KeyError, TypeError, ValueError):
            continue
        uname = str(u.get("username") or "").strip()
        uuid = _uuid_from_user(u)
        keys = {sid.lower(), uname.lower(), uuid.lower()}
        keys.discard("")
        if want and not (keys & want):
            continue
        for k in keys:
            mapping[k] = sid
        status[sid] = {
            "username": uname,
            "status": str(u.get("status") or "?").strip().lower() or "?",
            "watch_email": sid,
        }
    return mapping, status


def atomic_write(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def apply_aliases(mapping: dict[str, str]) -> int:
    if not DB_PATH.is_file() or not mapping:
        return 0
    inv: dict[str, set[str]] = {}
    for k, v in mapping.items():
        inv.setdefault(str(v).lower(), set()).update({str(k).lower(), str(v).lower()})

    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA busy_timeout=8000")
    rows = list(conn.execute("SELECT email, label, aliases FROM watchlist"))
    n = 0
    for email, label, aliases in rows:
        keys = {
            a.strip().lower()
            for a in (aliases or "").split(",")
            if a.strip()
        }
        for q in (email, label or "", mapping.get(str(email or "").lower(), "")):
            q = str(q or "").lower()
            if not q:
                continue
            if q in mapping:
                uid = str(mapping[q]).lower()
                keys.add(uid)
                keys.update(inv.get(uid, set()))
            if q in inv:
                keys.update(inv[q])
        keys.discard(str(email or "").lower())
        new_aliases = ",".join(sorted(keys))
        if new_aliases != (aliases or ""):
            conn.execute(
                "UPDATE watchlist SET aliases=? WHERE email=?",
                (new_aliases, email),
            )
            n += 1
    conn.commit()
    conn.close()
    return n


def apply_status(status: dict[str, dict], mapping: dict[str, str]) -> None:
    payload = {str(k): v for k, v in status.items() if isinstance(v, dict)}
    if not DB_PATH.is_file():
        atomic_write(STATUS_PATH, payload)
        return
    conn = sqlite3.connect(str(DB_PATH))
    rows = list(conn.execute("SELECT email, label, aliases FROM watchlist"))
    conn.close()
    for email, label, aliases in rows:
        keys = [str(email or "").lower(), str(label or "").lower()]
        for part in str(aliases or "").split(","):
            if part.strip():
                keys.append(part.strip().lower())
        uid = ""
        for k in keys:
            if k in mapping:
                uid = str(mapping[k])
                break
            if k.isdigit():
                uid = k
                break
        if uid and uid in payload:
            payload[uid]["watch_email"] = str(email or "").lower()
            continue
        miss_key = uid or str(email or label or "unknown").lower()
        payload[miss_key] = {
            "username": str(label or email or miss_key),
            "status": "missing",
            "watch_email": str(email or "").lower(),
        }
    atomic_write(STATUS_PATH, payload)


def main() -> None:
    names = watch_queries()
    mapping, status = resolve(names)
    atomic_write(MAP_PATH, mapping)
    updated = apply_aliases(mapping)
    apply_status(status, mapping)
    print(
        f"resolved={len(mapping)} queries={len(names)} "
        f"status={len(status)} aliases_updated={updated}"
    )


if __name__ == "__main__":
    main()
