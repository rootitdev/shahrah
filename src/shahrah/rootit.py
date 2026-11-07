"""Rootit: PasarGuard-backed subscription recovery portal.

PasarGuard remains the system of record for users and ``subscription_url``.
Rootit only:

* looks up ``GET /api/user/{username}`` via the existing :class:`PanelClient`
* rewrites the public host/port of that URL when the subscription domain dies
* optionally gates the page with a local PIN (can be disabled in emergencies)

Deploy on a *separate* resilient domain and point users there from your channel.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit, urlunsplit

from .models import ConfigError, validate_host, validate_port
from .panel import PanelClient, PanelError

_USER_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
# Short portal PIN: exactly 6 chars, lowercase letters + digits only (easy to dictate).
_PIN_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_PIN_RE = re.compile(r"^[a-z0-9]{6}$")
_PIN_LENGTH = 6
_DEFAULT_APOLOGY = (
    "بابت اختلال پیش‌آمده پوزش می‌طلبیم. لینک اشتراک به‌روز شما این است — "
    "آن را در کلاینت جایگزین کنید."
)


def generate_admin_token() -> str:
    return secrets.token_urlsafe(32)


def generate_pin() -> str:
    """Cryptographically random 6-char PIN from ``[a-z0-9]``."""
    return "".join(secrets.choice(_PIN_ALPHABET) for _ in range(_PIN_LENGTH))


def validate_pin(pin: str) -> str:
    if not _PIN_RE.fullmatch(pin):
        raise ConfigError("PIN must be exactly 6 characters: lowercase a-z and digits 0-9")
    return pin


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    """Legacy scrypt hash (kept for reading old configs). New PINs are stored plaintext."""
    validate_pin(password)
    salt_b = salt if salt is not None else secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt_b, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt_b.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    """Accept plaintext PIN or legacy ``scrypt$...`` hash."""
    if _PIN_RE.fullmatch(encoded or ""):
        return hmac.compare_digest(validate_pin(password), encoded)
    try:
        kind, salt_hex, hash_hex = encoded.split("$", 2)
    except ValueError:
        return False
    if kind != "scrypt":
        return False
    try:
        salt_b = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        validate_pin(password)
    except (ValueError, ConfigError):
        return False
    digest = hashlib.scrypt(password.encode(), salt=salt_b, n=2**14, r=8, p=1, dklen=32)
    return hmac.compare_digest(digest, expected)


def readable_pin(stored: str) -> str | None:
    """Return displayable PIN, or ``None`` when only a legacy hash is stored."""
    if _PIN_RE.fullmatch(stored or ""):
        return stored
    return None


def public_base(*, scheme: str, host: str, port: int) -> str:
    """``https://host`` or ``https://host:port`` when non-default."""
    scheme = scheme.lower()
    if scheme not in {"http", "https"}:
        raise ConfigError("public_scheme must be http or https")
    host = validate_host(host.lower(), "public_host")
    port = validate_port(port, "public_port")
    default = 443 if scheme == "https" else 80
    authority = host if port == default else f"{host}:{port}"
    return f"{scheme}://{authority}"


def apply_public_base(subscription_url: str, base: str) -> str:
    """Keep PasarGuard path/token; replace only the public origin.

    PasarGuard may return a relative path (``/sub/TOKEN``) or an absolute URL whose
    host is the dead domain. Either way the token path is preserved.
    """
    sub = (subscription_url or "").strip()
    if not sub:
        raise ConfigError("panel user has empty subscription_url")
    base = base.rstrip("/")
    base_parts = urlsplit(base if "://" in base else f"https://{base}")
    if not base_parts.scheme or not base_parts.netloc:
        raise ConfigError("public base must look like https://panel.example.com:2096")
    if sub.startswith("/"):
        return f"{base_parts.scheme}://{base_parts.netloc}{sub}"
    parts = urlsplit(sub)
    if not parts.path:
        raise ConfigError("subscription_url has no path")
    return urlunsplit(
        (base_parts.scheme, base_parts.netloc, parts.path, parts.query, parts.fragment)
    )


@dataclass
class RootitConfig:
    """Portal settings. Users live in PasarGuard; optional PINs are local only."""

    panel_url: str = "https://panel.example.com:8000"
    public_scheme: str = "https"
    public_host: str = "panel.example.com"
    public_port: int = 2096
    require_password: bool = False
    apology: str = _DEFAULT_APOLOGY
    admin_token: str = field(default_factory=generate_admin_token)
    pins: dict[str, str] = field(default_factory=dict)
    allow_insecure_http: bool = False
    insecure_tls: bool = False

    def base(self) -> str:
        return public_base(scheme=self.public_scheme, host=self.public_host, port=self.public_port)

    def as_dict(self) -> dict[str, Any]:
        return {
            "panel_url": self.panel_url,
            "public_scheme": self.public_scheme,
            "public_host": self.public_host,
            "public_port": self.public_port,
            "require_password": self.require_password,
            "apology": self.apology,
            "admin_token": self.admin_token,
            "pins": dict(sorted(self.pins.items())),
            "allow_insecure_http": self.allow_insecure_http,
            "insecure_tls": self.insecure_tls,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RootitConfig:
        panel_url = str(data.get("panel_url") or "").strip().rstrip("/")
        parts = urlsplit(panel_url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ConfigError("panel_url must look like https://panel.example.com:8000")
        scheme = str(data.get("public_scheme") or "https").lower()
        host = validate_host(str(data.get("public_host") or "").lower(), "public_host")
        port = validate_port(int(data.get("public_port") or 2096), "public_port")
        public_base(scheme=scheme, host=host, port=port)  # validate
        token = str(data.get("admin_token") or "").strip()
        if len(token) < 24:
            raise ConfigError("admin_token must be at least 24 characters")
        apology = str(data.get("apology") or _DEFAULT_APOLOGY).strip() or _DEFAULT_APOLOGY
        if len(apology) > 2000:
            raise ConfigError("apology text is too long")
        pins_raw = data.get("pins") or {}
        if not isinstance(pins_raw, dict):
            raise ConfigError("pins must be an object")
        pins: dict[str, str] = {}
        for name, encoded in pins_raw.items():
            if not _USER_RE.fullmatch(str(name)):
                raise ConfigError(f"invalid pin username: {name!r}")
            text = str(encoded or "").strip()
            if not text:
                continue
            # Plaintext PIN (preferred) or legacy scrypt hash from older installs.
            if _PIN_RE.fullmatch(text) or text.startswith("scrypt$"):
                pins[str(name)] = text
            else:
                raise ConfigError(f"pin for {name!r} must be 6×[a-z0-9] or a legacy scrypt hash")
        return cls(
            panel_url=panel_url,
            public_scheme=scheme,
            public_host=host,
            public_port=port,
            require_password=bool(data.get("require_password", False)),
            apology=apology,
            admin_token=token,
            pins=pins,
            allow_insecure_http=bool(data.get("allow_insecure_http", False)),
            insecure_tls=bool(data.get("insecure_tls", False)),
        )


def default_config() -> RootitConfig:
    return RootitConfig()


def load_config(path: Path) -> RootitConfig:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read rootit config: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid rootit JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("rootit config must be a JSON object")
    return RootitConfig.from_dict(data)


def save_config(path: Path, config: RootitConfig) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(config.as_dict(), indent=2, ensure_ascii=False) + "\n"
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(payload, encoding="utf-8")
        tmp.replace(path)
    except PermissionError:
        # systemd unit often owns the file but not the conf directory (cannot create .tmp).
        path.write_text(payload, encoding="utf-8")


def set_public_base(
    config: RootitConfig, *, host: str, port: int, scheme: str = "https"
) -> RootitConfig:
    return RootitConfig.from_dict(
        {
            **config.as_dict(),
            "public_host": host.lower(),
            "public_port": port,
            "public_scheme": scheme.lower(),
        }
    )


def set_pin(config: RootitConfig, username: str, pin: str) -> RootitConfig:
    """Store the PIN in plaintext so operators can list/export and users can re-read it."""
    if not _USER_RE.fullmatch(username):
        raise ConfigError("username must match [A-Za-z0-9._@-]{1,64}")
    pins = dict(config.pins)
    pins[username] = validate_pin(pin)
    return RootitConfig.from_dict({**config.as_dict(), "pins": pins})


def issue_pin(config: RootitConfig, username: str) -> tuple[RootitConfig, str]:
    """Generate a fresh 6-char PIN, store it, return ``(config, pin)``."""
    pin = generate_pin()
    return set_pin(config, username, pin), pin


def ensure_user_pin(config: RootitConfig, username: str) -> tuple[RootitConfig, str]:
    """Return existing readable PIN, or issue a new one (replaces legacy hashes)."""
    stored = config.pins.get(username, "")
    plain = readable_pin(stored)
    if plain:
        return config, plain
    return issue_pin(config, username)


def clear_pin(config: RootitConfig, username: str) -> RootitConfig:
    pins = dict(config.pins)
    pins.pop(username, None)
    return RootitConfig.from_dict({**config.as_dict(), "pins": pins})


def import_pins_lines(config: RootitConfig, text: str) -> tuple[RootitConfig, int]:
    """Import ``username|pin`` lines (PIN = 6× ``[a-z0-9]``). ``#`` comments ok."""
    count = 0
    current = config
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|", 1)]
        if len(parts) != 2 or not parts[1]:
            raise ConfigError(f"bad pin line (want username|pin): {raw!r}")
        current = set_pin(current, parts[0], parts[1])
        count += 1
    return current, count


def issue_pins_for_usernames(
    config: RootitConfig, usernames: list[str]
) -> tuple[RootitConfig, list[tuple[str, str]]]:
    """Issue a new PIN for each username. Returns ``(config, [(user, pin), ...])``."""
    current = config
    issued: list[tuple[str, str]] = []
    for name in usernames:
        name = name.strip()
        if not name or name.startswith("#"):
            continue
        current, pin = issue_pin(current, name)
        issued.append((name, pin))
    return current, issued


def panel_api_key() -> str:
    key = os.environ.get("SHAHRAH_PANEL_API_KEY", "").strip()
    if not key:
        raise ConfigError("set SHAHRAH_PANEL_API_KEY (PasarGuard API key)")
    return key


def make_panel_client(config: RootitConfig, *, api_key: str | None = None) -> PanelClient:
    return PanelClient(
        config.panel_url,
        api_key if api_key is not None else panel_api_key(),
        allow_insecure_http=config.allow_insecure_http,
        insecure_tls=config.insecure_tls,
    )


def resolve_subscription_url(
    client: PanelClient, config: RootitConfig, username: str
) -> tuple[str, dict[str, Any]]:
    """Fetch the PasarGuard user and return (rewritten public sub URL, user payload)."""
    if not _USER_RE.fullmatch(username):
        raise ConfigError("invalid username")
    try:
        user = client.get_user(username)
    except PanelError as exc:
        msg = str(exc)
        if "404" in msg:
            raise ConfigError("کاربر در پنل پاسارگارد پیدا نشد") from exc
        raise ConfigError(f"خطای پنل پاسارگارد: {exc}") from exc
    status = str(user.get("status") or "")
    if status.lower() == "disabled":
        raise ConfigError("این کاربر در پنل غیرفعال است")
    raw = str(user.get("subscription_url") or "")
    return apply_public_base(raw, config.base()), user


def _html_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def _page(title: str, body: str, *, status_msg: str = "", wide: bool = False) -> bytes:
    banner = f'<p class="ok">{_html_escape(status_msg)}</p>' if status_msg else ""
    main_class = ' class="wide"' if wide else ""
    html = f"""<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{_html_escape(title)}</title>
<style>
:root{{--bg:#0f1419;--card:#1a222c;--fg:#e7eef7;--muted:#9aa8b6;--acc:#3d9cf0;--err:#e35d6a;--ok:#3ecf8e}}
*{{box-sizing:border-box}}body{{margin:0;font:15px/1.55 system-ui,Tahoma,sans-serif;background:var(--bg);color:var(--fg)}}
main{{max-width:420px;margin:8vh auto;padding:1.25rem}}main.wide{{max-width:720px}}
h1{{font-size:1.15rem;margin:0 0 .75rem;font-weight:650}}
.card{{background:var(--card);border-radius:12px;padding:1.1rem 1.15rem;box-shadow:0 8px 28px #0006}}
label{{display:block;margin:.65rem 0 .25rem;color:var(--muted);font-size:.85rem}}
input,textarea{{width:100%;padding:.55rem .65rem;border-radius:8px;border:1px solid #2c3846;background:#12181f;color:var(--fg)}}
textarea{{min-height:6rem;font-family:ui-monospace,Consolas,monospace;font-size:12px}}
button,.btn{{display:inline-block;margin-top:.9rem;padding:.55rem .95rem;border:0;border-radius:8px;background:var(--acc);color:#041018;font-weight:650;cursor:pointer;text-decoration:none}}
.muted{{color:var(--muted);font-size:.9rem;margin:.4rem 0 0}}
.err{{color:var(--err)}}.ok{{color:var(--ok)}}
.linkbox{{word-break:break-all;background:#12181f;border:1px solid #2c3846;border-radius:8px;padding:.7rem;font-family:ui-monospace,Consolas,monospace;font-size:12px;direction:ltr;text-align:left}}
.row{{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center}}
.check{{display:flex;gap:.5rem;align-items:center;margin-top:.8rem;color:var(--muted)}}
.check input{{width:auto}}
nav{{display:flex;gap:.85rem;flex-wrap:wrap;margin-bottom:.85rem}}
nav a{{color:var(--acc);font-size:.85rem}}
#qr svg{{width:180px;height:180px;background:#fff;border-radius:8px;padding:6px}}
.pinbig{{font:700 2rem/1.2 ui-monospace,Consolas,monospace;letter-spacing:.18em;direction:ltr;text-align:center;padding:1rem;margin:.85rem 0;background:#12181f;border:1px solid #2c3846;border-radius:12px}}
table{{width:100%;border-collapse:collapse;font-size:.9rem;margin-top:.75rem}}
th,td{{border-bottom:1px solid #2c3846;padding:.45rem .35rem;text-align:right}}
td.pin,th.pin{{direction:ltr;text-align:left;font-family:ui-monospace,Consolas,monospace;letter-spacing:.08em}}
.pager{{display:flex;gap:.5rem;align-items:center;justify-content:space-between;margin-top:1rem;flex-wrap:wrap}}
.btn.secondary{{background:#2c3846;color:var(--fg)}}
.btn.small{{margin-top:0;padding:.35rem .55rem;font-size:.8rem}}
</style>
</head>
<body><main{main_class}><div class="card"><h1>{_html_escape(title)}</h1>{banner}{body}</div></main></body></html>"""
    return html.encode("utf-8")


def _qr_js_bytes() -> bytes:
    path = Path(__file__).resolve().parent / "data" / "qrcode.min.js"
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"missing bundled qrcode.min.js: {exc}") from exc


def _user_form(*, require_password: bool, error: str = "") -> bytes:
    pw = (
        '<label>PIN شش‌کاراکتری</label><input name="password" type="text" inputmode="text" autocomplete="one-time-code" maxlength="6" pattern="[a-z0-9]{6}" placeholder="مثلا ab12cd">'
        if require_password
        else '<p class="muted">حالت اضطراری: فقط نام کاربری پنل پاسارگارد کافی است.</p>'
    )
    err = f'<p class="err">{_html_escape(error)}</p>' if error else ""
    body = f"""
<p class="muted">پنل اشتراک کاربران روتیت — لینک از پاسارگارد با دامنهٔ فعال.</p>
{err}
<form method="post" action="/mysub" autocomplete="on">
<label>نام کاربری</label>
<input name="username" required maxlength="64" autocomplete="username" autofocus>
{pw}
<button type="submit">نمایش لینک</button>
</form>"""
    return _page("پنل اشتراک روتیت", body)


def _user_result(*, username: str, url: str, apology: str, pin: str) -> bytes:
    safe = _html_escape(url)
    js_url = json.dumps(url, ensure_ascii=False)
    js_pin = json.dumps(pin, ensure_ascii=False)
    body = f"""
<p>{_html_escape(apology)}</p>
<p class="muted">کاربر: <b>{_html_escape(username)}</b></p>
<p class="muted" style="margin-top:1rem">رمز ورود شما (یادداشت کنید — برای دفعات بعد لازم است):</p>
<div class="pinbig" id="pinbox">{_html_escape(pin)}</div>
<div class="row"><button type="button" class="btn secondary" id="copypin">کپی رمز</button></div>
<p class="muted" style="margin-top:1.2rem">لینک اشتراک:</p>
<div class="linkbox" id="suburl">{safe}</div>
<div class="row">
<button type="button" id="copy">کپی لینک</button>
<a class="btn" href="{quote(url, safe=":/?&=%._~-")}">باز کردن</a>
</div>
<div id="qr" style="display:flex;justify-content:center;margin-top:1rem"></div>
<script src="/qr.js"></script>
<script>
(function(){{
  var url={js_url}, pin={js_pin};
  function copyOf(text, btn){{
    return async function(){{
      try{{await navigator.clipboard.writeText(text);btn.textContent='کپی شد'}}
      catch(e){{
        var t=document.createElement('textarea');t.value=text;document.body.appendChild(t);t.select();
        document.execCommand('copy');t.remove();btn.textContent='کپی شد';
      }}
    }};
  }}
  try{{
    var qr=qrcode(0,'M');
    qr.addData(url);
    qr.make();
    document.getElementById('qr').innerHTML=qr.createSvgTag(4,0);
  }}catch(e){{}}
  document.getElementById('copy').onclick=copyOf(url, document.getElementById('copy'));
  document.getElementById('copypin').onclick=copyOf(pin, document.getElementById('copypin'));
}})();
</script>
<p class="muted"><a href="/mysub">بازگشت</a></p>"""
    return _page("لینک اشتراک", body)


def _admin_nav() -> str:
    return (
        "<nav>"
        '<a href="/admin/settings">تنظیمات</a>'
        '<a href="/admin/users">کاربران و رمزها</a>'
        '<a href="/mysub">صفحه کاربر</a>'
        "</nav>"
    )


def _admin_token_script() -> str:
    return """
<script>
(function(){
  var t=sessionStorage.getItem('rootit_admin')||'';
  document.querySelectorAll('form').forEach(function(f){
    var h=f.querySelector('input[name=admin_token]');
    if(h) h.value=t;
    else {var i=document.createElement('input');i.type='hidden';i.name='admin_token';i.value=t;f.appendChild(i)}
  });
  document.querySelectorAll('a[data-need-token]').forEach(function(a){
    var u=new URL(a.href, location.origin);
    u.searchParams.set('admin_token', t);
    a.href=u.toString();
  });
})();
</script>"""


def _admin_form(config: RootitConfig, *, msg: str = "", error: str = "") -> bytes:
    err = f'<p class="err">{_html_escape(error)}</p>' if error else ""
    checked = "checked" if config.require_password else ""
    body = f"""
{_admin_nav()}
{err}
<p class="muted">دامنهٔ عمومی ساب و حالت اضطراری (بدون PIN) را اینجا تنظیم کنید.</p>
<form method="post" action="/admin/settings">
<label>آدرس API پنل پاسارگارد</label>
<input name="panel_url" value="{_html_escape(config.panel_url)}" required>
<label>دامنهٔ عمومی ساب (host)</label>
<input name="public_host" value="{_html_escape(config.public_host)}" required>
<label>پورت عمومی ساب</label>
<input name="public_port" type="number" min="1" max="65535" value="{config.public_port}" required>
<label>طرح (https/http)</label>
<input name="public_scheme" value="{_html_escape(config.public_scheme)}" required>
<label>پیام عذرخواهی</label>
<textarea name="apology">{_html_escape(config.apology)}</textarea>
<label class="check"><input name="require_password" type="checkbox" value="1" {checked}> برای ورود کاربر PIN لازم باشد (خاموش = حالت اضطراری)</label>
<button type="submit">ذخیره</button>
</form>
<hr style="border:0;border-top:1px solid #2c3846;margin:1.2rem 0">
<form method="post" action="/admin/import-pins">
<label>وارد کردن دستی (هر خط: username|pin)</label>
<textarea name="pins" placeholder="ali|ab12cd"></textarea>
<button type="submit">Import PIN</button>
</form>
<p class="muted">تعداد رمز ذخیره‌شده: {len(config.pins)}</p>
{_admin_token_script()}"""
    return _page("تنظیمات روتیت", body, status_msg=msg, wide=True)


def _admin_users_page(
    config: RootitConfig, *, page: int = 1, per_page: int = 50, msg: str = "", error: str = ""
) -> bytes:
    rows = sorted(config.pins.items(), key=lambda kv: kv[0].lower())
    total = len(rows)
    per_page = max(1, min(per_page, 200))
    pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, pages))
    start = (page - 1) * per_page
    chunk = rows[start : start + per_page]
    err = f'<p class="err">{_html_escape(error)}</p>' if error else ""
    trs = []
    for i, (user, stored) in enumerate(chunk, start=start + 1):
        pin = readable_pin(stored) or "—"
        pin_js = json.dumps(pin if pin != "—" else "")
        trs.append(
            f"<tr><td>{i}</td><td>{_html_escape(user)}</td>"
            f'<td class="pin" id="p{i}">{_html_escape(pin)}</td>'
            f'<td><button type="button" class="btn small secondary" data-pin={pin_js}>کپی</button></td></tr>'
        )
    table = (
        "<table><thead><tr><th>#</th><th>یوزرنیم</th><th class='pin'>رمز</th><th></th></tr></thead>"
        f"<tbody>{''.join(trs) or '<tr><td colspan=4>هنوز رمزی نیست — از دکمهٔ ساخت استفاده کنید</td></tr>'}"
        "</tbody></table>"
    )
    prev_dis = "opacity:.4;pointer-events:none" if page <= 1 else ""
    next_dis = "opacity:.4;pointer-events:none" if page >= pages else ""
    body = f"""
{_admin_nav()}
{err}
<p class="muted">لیست رمزهای محلی روتیت (قابل نمایش/خروجی). یوزرنیم باید در پاسارگارد هم وجود داشته باشد.</p>
<div class="row">
<form method="post" action="/admin/issue-missing" style="display:inline">
<button type="submit">ساخت رمز برای یوزرهای پاسارگارد بدون رمز</button>
</form>
<a class="btn secondary" data-need-token href="/admin/export-pins">دانلود Export (CSV)</a>
</div>
{table}
<div class="pager">
<a data-need-token href="/admin/users?page={page - 1}" style="{prev_dis}">قبلی</a>
<span class="muted">صفحه {page} از {pages} — جمع {total}</span>
<a data-need-token href="/admin/users?page={page + 1}" style="{next_dis}">بعدی</a>
</div>
<script>
document.querySelectorAll('button[data-pin]').forEach(function(b){{
  b.onclick=async function(){{
    var pin=b.getAttribute('data-pin')||'';
    if(!pin) return;
    try{{await navigator.clipboard.writeText(pin);b.textContent='کپی شد'}}
    catch(e){{var t=document.createElement('textarea');t.value=pin;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove();b.textContent='کپی شد'}}
  }};
}});
</script>
{_admin_token_script()}"""
    return _page("کاربران و رمزها", body, status_msg=msg, wide=True)


def export_pins_csv(config: RootitConfig) -> str:
    lines = ["username,pin"]
    for user, stored in sorted(config.pins.items(), key=lambda kv: kv[0].lower()):
        pin = readable_pin(stored) or ""
        lines.append(f"{user},{pin}")
    return "\n".join(lines) + "\n"


def issue_pins_for_panel_users(
    config: RootitConfig, client: PanelClient, *, limit: int = 5000
) -> tuple[RootitConfig, int]:
    """Create a PIN for every PasarGuard username that does not yet have a readable PIN."""
    created = 0
    current = config
    offset = 0
    page_size = 100
    while offset < limit:
        data = client.list_users(offset=offset, limit=page_size)
        users = data.get("users", []) if isinstance(data, dict) else []
        if not isinstance(users, list) or not users:
            break
        for row in users:
            if not isinstance(row, dict):
                continue
            name = str(row.get("username") or "").strip()
            if not name:
                continue
            if readable_pin(current.pins.get(name, "")):
                continue
            current, _pin = issue_pin(current, name)
            created += 1
        if len(users) < page_size:
            break
        offset += page_size
    return current, created


def _admin_login(*, error: str = "") -> bytes:
    err = f'<p class="err">{_html_escape(error)}</p>' if error else ""
    body = f"""
{err}
<form method="post" action="/admin/login">
<label>توکن ادمین</label>
<input name="admin_token" type="password" required autofocus>
<button type="submit">ورود</button>
</form>"""
    return _page("ورود ادمین", body)


class _RateLimit:
    def __init__(self, *, limit: int = 30, window: float = 60.0) -> None:
        self.limit = limit
        self.window = window
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = [t for t in self._hits.get(key, []) if now - t < self.window]
            if len(bucket) >= self.limit:
                self._hits[key] = bucket
                return False
            bucket.append(now)
            self._hits[key] = bucket
            return True


def make_handler(config_path: Path) -> type[BaseHTTPRequestHandler]:
    limiter = _RateLimit()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def _client(self) -> str:
            return self.client_address[0]

        def _send(
            self,
            code: int,
            body: bytes,
            *,
            content_type: str = "text/html; charset=utf-8",
            set_cookie: str | None = None,
        ) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if set_cookie:
                self.send_header("Set-Cookie", set_cookie)
            self.end_headers()
            self.wfile.write(body)

        def _read_form(self) -> dict[str, str]:
            length = int(self.headers.get("Content-Length") or 0)
            if length < 0 or length > 200_000:
                raise ConfigError("body too large")
            raw = self.rfile.read(length) if length else b""
            parsed = parse_qs(raw.decode("utf-8", errors="replace"), keep_blank_values=True)
            return {k: (v[-1] if v else "") for k, v in parsed.items()}

        def _cfg(self) -> RootitConfig:
            return load_config(config_path)

        def _admin_token_from_request(self, form: dict[str, str] | None = None) -> str:
            if form and form.get("admin_token"):
                return form["admin_token"]
            header = self.headers.get("X-Rootit-Token") or ""
            if header:
                return header
            qs = parse_qs(urlsplit(self.path).query)
            if qs.get("admin_token"):
                return qs["admin_token"][-1]
            jar = SimpleCookie()
            jar.load(self.headers.get("Cookie", ""))
            morsel = jar.get("rootit_admin")
            return morsel.value if morsel else ""

        def _check_admin(self, cfg: RootitConfig, form: dict[str, str] | None = None) -> bool:
            token = self._admin_token_from_request(form)
            return bool(token) and hmac.compare_digest(token, cfg.admin_token)

        def _admin_cookie(self, token: str) -> str:
            return f"rootit_admin={token}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=86400"

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            path = parsed.path.rstrip("/") or "/"
            qs = parse_qs(parsed.query)
            if path in {"/", "/mysub"}:
                cfg = self._cfg()
                return self._send(200, _user_form(require_password=cfg.require_password))
            if path == "/health":
                return self._send(200, b"ok\n", content_type="text/plain; charset=utf-8")
            if path == "/qr.js":
                body = _qr_js_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/admin":
                return self._send(200, _admin_login())
            cfg = self._cfg()
            if path in {"/admin/settings", "/admin/users", "/admin/export-pins"}:
                if not self._check_admin(cfg):
                    return self._send(403, _admin_login(error="وارد ادمین شوید"))
                if path == "/admin/settings":
                    return self._send(200, _admin_form(cfg))
                if path == "/admin/export-pins":
                    csv = export_pins_csv(cfg).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/csv; charset=utf-8")
                    self.send_header(
                        "Content-Disposition", 'attachment; filename="rootit-pins.csv"'
                    )
                    self.send_header("Content-Length", str(len(csv)))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(csv)
                    return
                try:
                    page = int((qs.get("page") or ["1"])[-1])
                except ValueError:
                    page = 1
                return self._send(200, _admin_users_page(cfg, page=page))
            self._send(404, _page("یافت نشد", '<p class="err">404</p>'))

        def do_POST(self) -> None:
            if not limiter.allow(self._client()):
                return self._send(
                    429,
                    _page(
                        "کمی صبر",
                        '<p class="err">تعداد درخواست زیاد است. کمی بعد دوباره تلاش کنید.</p>',
                    ),
                )
            path = urlsplit(self.path).path.rstrip("/") or "/"
            try:
                form = self._read_form()
            except ConfigError:
                return self._send(400, _page("خطا", '<p class="err">درخواست نامعتبر</p>'))
            cfg = self._cfg()
            if path == "/mysub":
                return self._login_user(cfg, form)
            if path == "/admin/login":
                if not self._check_admin(cfg, form):
                    return self._send(403, _admin_login(error="توکن نادرست"))
                token = form.get("admin_token", "")
                token_js = json.dumps(token)
                page = _admin_form(cfg, msg="وارد شدید")
                inject = (
                    f"<script>sessionStorage.setItem('rootit_admin',{token_js});</script>"
                ).encode()
                page = page.replace(b"</main>", inject + b"</main>", 1)
                return self._send(200, page, set_cookie=self._admin_cookie(token))
            if path == "/admin/settings":
                if not self._check_admin(cfg, form):
                    return self._send(403, _admin_login(error="توکن نادرست"))
                try:
                    updated = RootitConfig.from_dict(
                        {
                            **cfg.as_dict(),
                            "panel_url": form.get("panel_url", "").strip(),
                            "public_host": form.get("public_host", "").strip(),
                            "public_port": int(form.get("public_port") or 0),
                            "public_scheme": form.get("public_scheme", "https").strip(),
                            "require_password": form.get("require_password") == "1",
                            "apology": form.get("apology") or _DEFAULT_APOLOGY,
                        }
                    )
                    save_config(config_path, updated)
                except (ConfigError, ValueError) as exc:
                    return self._send(400, _admin_form(cfg, error=str(exc)))
                return self._send(
                    200,
                    _admin_form(
                        updated,
                        msg="ذخیره شد — لینک‌ها با دامنهٔ جدید از روی توکن پاسارگارد ساخته می‌شوند.",
                    ),
                )
            if path == "/admin/import-pins":
                if not self._check_admin(cfg, form):
                    return self._send(403, _admin_login(error="توکن نادرست"))
                try:
                    updated, n = import_pins_lines(cfg, form.get("pins") or "")
                    save_config(config_path, updated)
                except ConfigError as exc:
                    return self._send(400, _admin_users_page(cfg, error=str(exc)))
                return self._send(200, _admin_users_page(updated, msg=f"{n} رمز ذخیره شد"))
            if path == "/admin/issue-missing":
                if not self._check_admin(cfg, form):
                    return self._send(403, _admin_login(error="توکن نادرست"))
                try:
                    client = make_panel_client(cfg)
                    updated, n = issue_pins_for_panel_users(cfg, client)
                    save_config(config_path, updated)
                except (ConfigError, PanelError) as exc:
                    return self._send(400, _admin_users_page(cfg, error=str(exc)))
                return self._send(
                    200,
                    _admin_users_page(updated, msg=f"{n} رمز جدید برای یوزرهای بدون رمز ساخته شد"),
                )
            self._send(404, _page("یافت نشد", '<p class="err">404</p>'))

        def _login_user(self, cfg: RootitConfig, form: dict[str, str]) -> None:
            username = (form.get("username") or "").strip()
            password = form.get("password") or ""
            if not _USER_RE.fullmatch(username):
                return self._send(
                    400,
                    _user_form(require_password=cfg.require_password, error="نام کاربری نامعتبر"),
                )
            if cfg.require_password:
                encoded = cfg.pins.get(username, "")
                if not encoded or not verify_password(password, encoded):
                    return self._send(
                        403,
                        _user_form(require_password=cfg.require_password, error="رمز نادرست"),
                    )
            try:
                client = make_panel_client(cfg)
                url, _user = resolve_subscription_url(client, cfg, username)
                cfg2, pin = ensure_user_pin(cfg, username)
                if cfg2 is not cfg or cfg.pins.get(username) != cfg2.pins.get(username):
                    save_config(config_path, cfg2)
            except ConfigError as exc:
                return self._send(
                    403,
                    _user_form(require_password=cfg.require_password, error=str(exc)),
                )
            return self._send(
                200,
                _user_result(username=username, url=url, apology=cfg2.apology, pin=pin),
            )

    return Handler


def serve(
    config_path: Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8790,
    forever: bool = True,
) -> ThreadingHTTPServer:
    public_all = "0.0.0.0"  # noqa: S104
    if host not in {"127.0.0.1", "::1", "localhost", public_all}:
        raise ConfigError("rootit listen address must be loopback or 0.0.0.0")
    load_config(config_path)
    server = ThreadingHTTPServer((host, port), make_handler(config_path))
    if forever:
        server.serve_forever()
    else:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
