#!/usr/bin/env python3
"""Web UI for Shahrah backhaul path selection (stdlib only)."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

CFG_PATH = Path(os.environ.get("PATH_WEB_CFG", "/etc/path-web/config.env"))
LOGIN_WINDOW = 60.0
LOGIN_MAX = 12

_cfg: dict[str, str] = {}
_login_hits: dict[str, list[float]] = {}


def _parse_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = ln.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def load_cfg() -> dict[str, str]:
    d = {
        "LISTEN": "127.0.0.1:8791",
        "AUTH_USER": "path",
        "COOKIE_NAME": "shahpath",
        "SHAHRAH_BIN": "/usr/local/bin/shahrah",
    }
    d.update(_parse_env(CFG_PATH))
    return d


def verify_password(password: str) -> bool:
    raw = _cfg.get("AUTH_HASH") or ""
    parts = raw.split("$")
    if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
        return False
    try:
        iters = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expect = bytes.fromhex(parts[3])
    except ValueError:
        return False
    got = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
    return hmac.compare_digest(got, expect)


def make_session() -> str:
    exp = str(int(time.time()) + 7 * 24 * 3600)
    user = _cfg.get("AUTH_USER") or "path"
    msg = f"{exp}:{user}".encode()
    sig = hmac.new((_cfg.get("SESSION_SECRET") or "").encode(), msg, hashlib.sha256).hexdigest()
    return f"{exp}:{sig}"


def valid_session(token: str) -> bool:
    if not token or ":" not in token:
        return False
    exp_s, sig = token.split(":", 1)
    try:
        exp = int(exp_s)
    except ValueError:
        return False
    if exp < int(time.time()):
        return False
    user = _cfg.get("AUTH_USER") or "path"
    msg = f"{exp}:{user}".encode()
    expect = hmac.new((_cfg.get("SESSION_SECRET") or "").encode(), msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expect)


def shahrah_json(*args: str) -> dict:
    cmd = [_cfg.get("SHAHRAH_BIN") or "shahrah", *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90, check=False)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "shahrah failed").strip())
    return json.loads(proc.stdout)


def page_layout(title: str, body: str) -> bytes:
    html = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{title}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #0f1419; color: #e7e9ea; }}
a {{ color: #1d9bf0; }}
.card {{ background: #16202a; border-radius: 12px; padding: 1rem 1.2rem; margin: 1rem 0; }}
.ok {{ color: #00ba7c; }} .bad {{ color: #f4212e; }}
button {{ padding: 0.5rem 1rem; border-radius: 8px; border: 0; background: #1d9bf0; color: #fff; }}
input[type=password], input[type=text] {{ padding: 0.5rem; border-radius: 8px; border: 1px solid #38444d; background:#15202b; color:#fff; }}
</style>
</head>
<body>
<h1>{title}</h1>
{body}
<p><small>CLI: <code>shahrah backhaul status</code> · timer: <code>shahrah-backhaul-failover.timer</code></small></p>
</body></html>"""
    return html.encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "path-web/1"

    def _cookie(self) -> str:
        raw = self.headers.get("Cookie") or ""
        name = _cfg.get("COOKIE_NAME") or "shahpath"
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith(name + "="):
                return part.split("=", 1)[1]
        return ""

    def _auth(self) -> bool:
        return valid_session(self._cookie())

    def _login_rate_ok(self, ip: str) -> bool:
        now = time.time()
        hits = [t for t in _login_hits.get(ip, []) if now - t < LOGIN_WINDOW]
        _login_hits[ip] = hits
        return len(hits) < LOGIN_MAX

    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/status" and self._auth():
            try:
                data = shahrah_json("backhaul", "status", "--json")
            except (RuntimeError, json.JSONDecodeError) as exc:
                self._send(500, json.dumps({"error": str(exc)}).encode(), "application/json")
                return
            self._send(200, json.dumps(data, ensure_ascii=False).encode(), "application/json")
            return
        if path in ("/", "/path/", "/path") and self._auth():
            try:
                st = shahrah_json("backhaul", "status", "--json")
            except (RuntimeError, json.JSONDecodeError) as exc:
                self._send(500, page_layout("مسیر بک‌هال", f"<p class='bad'>{exc}</p>"))
                return
            rows = []
            for row in st.get("paths") or []:
                mark = "★" if row.get("active") else ""
                cls = "ok" if row.get("healthy") else "bad"
                rows.append(
                    f"<tr><td>{mark}</td><td><code>{row['id']}</code></td>"
                    f"<td class='{cls}'>{'سالم' if row.get('healthy') else 'خراب'}</td>"
                    f"<td>{row.get('title_fa', '')}</td>"
                    f"<td><form method='post' action='/set'>"
                    f"<input type='hidden' name='path_id' value='{row['id']}'/>"
                    f"<button type='submit'>انتخاب</button></form></td></tr>"
                )
            body = f"""
<p>کنترل: <b>{st.get('control')}</b> — مسیر فعال: <code>{st.get('active')}</code></p>
<form method="post" action="/auto"><button type="submit">برگشت به حالت خودکار</button></form>
<table cellpadding="8"><tr><th></th><th>id</th><th>سلامت</th><th>توضیح</th><th></th></tr>
{''.join(rows)}</table>
"""
            self._send(200, page_layout("انتخاب مسیر بک‌هال", body))
            return
        if path in ("/", "/path/", "/path"):
            form = """
<form method="post" action="/login">
<label>کاربر <input name="user" value="path"/></label><br/><br/>
<label>رمز <input type="password" name="pass" autofocus/></label><br/><br/>
<button type="submit">ورود</button>
</form>"""
            self._send(200, page_layout("ورود path-web", form))
            return
        self._send(404, b"not found")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        fields = {k: v[0] for k, v in parse_qs(raw).items()}
        path = urlparse(self.path).path
        ip = self.client_address[0]
        if path == "/login":
            if not self._login_rate_ok(ip):
                self._send(429, page_layout("ورود", "<p class='bad'>تعداد تلاش زیاد</p>"))
                return
            _login_hits.setdefault(ip, []).append(time.time())
            user = fields.get("user", "")
            pwd = fields.get("pass", "")
            if user == (_cfg.get("AUTH_USER") or "path") and verify_password(pwd):
                tok = make_session()
                name = _cfg.get("COOKIE_NAME") or "shahpath"
                self.send_response(303)
                self.send_header("Location", "/path/")
                self.send_header("Set-Cookie", f"{name}={tok}; HttpOnly; Path=/; SameSite=Lax")
                self.end_headers()
                return
            self._send(403, page_layout("ورود", "<p class='bad'>رمز اشتباه</p>"))
            return
        if not self._auth():
            self._send(403, b"login required")
            return
        cmd: list[str] | None = None
        if path == "/set":
            pid = fields.get("path_id", "")
            if pid:
                cmd = ["backhaul", "set", pid]
        elif path == "/auto":
            cmd = ["backhaul", "auto"]
        if not cmd:
            self._send(400, b"bad request")
            return
        try:
            proc = subprocess.run(
                [_cfg.get("SHAHRAH_BIN") or "shahrah", *cmd],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr or proc.stdout)
        except (OSError, RuntimeError) as exc:
            self._send(500, page_layout("خطا", f"<p class='bad'>{exc}</p>"))
            return
        self.send_response(303)
        self.send_header("Location", "/path/")
        self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main() -> None:
    global _cfg
    _cfg = load_cfg()
    if not (_cfg.get("AUTH_HASH") or _cfg.get("SESSION_SECRET")):
        print("config missing AUTH_HASH / SESSION_SECRET", file=sys.stderr)
        sys.exit(2)
    host, _, port_s = (_cfg.get("LISTEN") or "127.0.0.1:8791").partition(":")
    port = int(port_s or "8791")
    srv = ThreadingHTTPServer((host or "127.0.0.1", port), Handler)
    print(f"path-web on http://{host or '127.0.0.1'}:{port}/path/")  # noqa: T201
    srv.serve_forever()


if __name__ == "__main__":
    main()