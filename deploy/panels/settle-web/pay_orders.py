"""Self-serve retail top-up orders for settle-web (/pay/)."""
from __future__ import annotations

import json
import secrets
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

GIB = 1024**3
ORDER_TTL_SEC = 10 * 60  # 10 minutes for customer card transfer
PAY_SUFFIX_DIGITS = 3  # default; overridable via create_order(suffix_digits=)
SECRETS_PATH = Path("/root/.vpn-secrets/.env")


def _panel_base() -> str:
    s = _parse_env(SECRETS_PATH)
    for k in ("MASTER_PANEL_URL", "PANEL_BASE_URL", "PANEL_URL"):
        v = (s.get(k) or "").strip().rstrip("/")
        if v.startswith("http"):
            return v
    return "http://127.0.0.1:8000"


PANEL_BASE = None  # resolved at request time via _panel_base()


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


def panel_api_key() -> str:
    return (_parse_env(SECRETS_PATH).get("PANEL_API_KEY") or "").strip()


DEFAULT_SLOGAN = (
    "همکاران گرامی جهت خرید لوازم جانبی نام کاربری و رمز عبور را وارد کنید"
)
UNLIMITED_ADMIN_ID = 1  # only this panel admin may sell unlimited plans

SELLER_EXTRA_COLS = {
    "card_number": "TEXT NOT NULL DEFAULT ''",
    "card_name": "TEXT NOT NULL DEFAULT ''",
    "business_name": "TEXT NOT NULL DEFAULT ''",
    "telegram_channel": "TEXT NOT NULL DEFAULT ''",
    "support_phone": "TEXT NOT NULL DEFAULT ''",
    "support_telegram": "TEXT NOT NULL DEFAULT ''",
    "slogan": "TEXT NOT NULL DEFAULT ''",
    # auto = SMS Forwarder; manual = admin confirms in settle
    "pay_confirm_mode": "TEXT NOT NULL DEFAULT 'manual'",
    # Per-admin webhook secret so one reseller's SMS cannot fulfill another's orders
    "sms_webhook_token": "TEXT NOT NULL DEFAULT ''",
    # Unique transfer amount suffix length (3 → 25000 stays ~25xxx, not 30xxx)
    "pay_suffix_digits": "INTEGER NOT NULL DEFAULT 3",
}


def ensure_tables(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(seller)").fetchall()}
    for name, decl in SELLER_EXTRA_COLS.items():
        if name not in cols:
            conn.execute(f"ALTER TABLE seller ADD COLUMN {name} {decl}")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS pay_plan (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            gib REAL NOT NULL,
            days INTEGER NOT NULL,
            price_toman INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_ts REAL NOT NULL
        )"""
    )
    pcols = {r[1] for r in conn.execute("PRAGMA table_info(pay_plan)").fetchall()}
    if "user_count" not in pcols:
        conn.execute(
            "ALTER TABLE pay_plan ADD COLUMN user_count INTEGER NOT NULL DEFAULT 1"
        )
    if "description" not in pcols:
        conn.execute(
            "ALTER TABLE pay_plan ADD COLUMN description TEXT NOT NULL DEFAULT ''"
        )
    if "fair_use" not in pcols:
        conn.execute(
            "ALTER TABLE pay_plan ADD COLUMN fair_use INTEGER NOT NULL DEFAULT 0"
        )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pay_plan_admin ON pay_plan(admin_id, active)"
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS pay_order (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL DEFAULT '',
            plan_id INTEGER,
            gib REAL NOT NULL,
            days INTEGER NOT NULL,
            price_toman INTEGER NOT NULL,
            pay_amount INTEGER NOT NULL,
            status TEXT NOT NULL,
            ts REAL NOT NULL,
            expires_ts REAL NOT NULL,
            paid_ts REAL,
            detail TEXT NOT NULL DEFAULT ''
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pay_order_pending_amt ON pay_order(status, pay_amount)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pay_order_user ON pay_order(username, status)"
    )
    # Resellers cannot keep selling unlimited packs.
    conn.execute(
        "UPDATE pay_plan SET active=0 WHERE admin_id!=? AND gib<=0 AND active=1",
        (UNLIMITED_ADMIN_ID,),
    )


def expire_orders(conn: sqlite3.Connection, now: float | None = None) -> int:
    now = time.time() if now is None else float(now)
    cur = conn.execute(
        "UPDATE pay_order SET status='expired', detail='مهلت پرداخت تمام شد' "
        "WHERE status='pending' AND expires_ts < ?",
        (now,),
    )
    return int(cur.rowcount or 0)


def _seller_brand_defaults() -> dict:
    return {
        "card_number": "",
        "card_name": "",
        "business_name": "",
        "telegram_channel": "",
        "support_phone": "",
        "support_telegram": "",
        "slogan": DEFAULT_SLOGAN,
        "pay_confirm_mode": "manual",
        "sms_webhook_token": "",
        "pay_suffix_digits": PAY_SUFFIX_DIGITS,
    }


def normalize_pay_mode(mode: str | None) -> str:
    m = (mode or "manual").strip().lower()
    return "auto" if m == "auto" else "manual"


def get_seller_shop(conn: sqlite3.Connection, admin_id: int) -> dict:
    row = conn.execute("SELECT * FROM seller WHERE admin_id=?", (admin_id,)).fetchone()
    out = _seller_brand_defaults()
    if not row:
        return out
    out["card_number"] = str(row["card_number"] or "") if "card_number" in row.keys() else ""
    out["card_name"] = str(row["card_name"] or "") if "card_name" in row.keys() else ""
    for k in (
        "business_name",
        "telegram_channel",
        "support_phone",
        "support_telegram",
        "slogan",
        "pay_confirm_mode",
        "sms_webhook_token",
    ):
        if k in row.keys():
            out[k] = str(row[k] or "")
    if "pay_suffix_digits" in row.keys() and row["pay_suffix_digits"] is not None:
        try:
            out["pay_suffix_digits"] = max(1, min(6, int(row["pay_suffix_digits"])))
        except (TypeError, ValueError):
            out["pay_suffix_digits"] = PAY_SUFFIX_DIGITS
    if not (out.get("slogan") or "").strip():
        out["slogan"] = DEFAULT_SLOGAN
    out["pay_confirm_mode"] = normalize_pay_mode(out.get("pay_confirm_mode"))
    return out


def ensure_seller_sms_token(conn: sqlite3.Connection, admin_id: int) -> str:
    """Return (and create if needed) a unique webhook token for this admin."""
    ensure_tables(conn)
    admin_id = int(admin_id)
    row = conn.execute(
        "SELECT sms_webhook_token FROM seller WHERE admin_id=?", (admin_id,)
    ).fetchone()
    if row:
        tok = str(row["sms_webhook_token"] or "").strip()
        if tok:
            return tok
    for _ in range(8):
        cand = secrets.token_urlsafe(24)
        hit = conn.execute(
            "SELECT admin_id FROM seller WHERE sms_webhook_token=?", (cand,)
        ).fetchone()
        if hit:
            continue
        if row is not None:
            conn.execute(
                "UPDATE seller SET sms_webhook_token=? WHERE admin_id=?",
                (cand, admin_id),
            )
        else:
            conn.execute(
                "INSERT INTO seller(admin_id, price, debt_toman, sms_webhook_token) "
                "VALUES (?,?,0,?)",
                (admin_id, 2500, cand),
            )
        return cand
    raise RuntimeError("نتوانستیم توکن پیامک ادمین بسازیم.")


def find_admin_by_sms_token(conn: sqlite3.Connection, token: str) -> int | None:
    tok = (token or "").strip()
    if not tok:
        return None
    ensure_tables(conn)
    row = conn.execute(
        "SELECT admin_id FROM seller WHERE sms_webhook_token=? LIMIT 1", (tok,)
    ).fetchone()
    return int(row["admin_id"]) if row else None


def seller_pay_mode(conn: sqlite3.Connection, admin_id: int) -> str:
    return get_seller_shop(conn, admin_id)["pay_confirm_mode"]


def get_seller_card(conn: sqlite3.Connection, admin_id: int) -> dict:
    shop = get_seller_shop(conn, admin_id)
    return {"card_number": shop["card_number"], "card_name": shop["card_name"]}


def set_seller_shop(
    conn: sqlite3.Connection,
    admin_id: int,
    *,
    card_number: str | None = None,
    card_name: str | None = None,
    business_name: str | None = None,
    telegram_channel: str | None = None,
    support_phone: str | None = None,
    support_telegram: str | None = None,
    slogan: str | None = None,
    pay_confirm_mode: str | None = None,
    pay_suffix_digits: int | None = None,
) -> dict:
    """Update shop/branding fields; None keeps existing value."""
    admin_id = int(admin_id)
    cur = get_seller_shop(conn, admin_id)
    if card_number is not None:
        cur["card_number"] = "".join(ch for ch in card_number if ch.isdigit())[:24]
    if card_name is not None:
        cur["card_name"] = (card_name or "").strip()[:80]
    if business_name is not None:
        cur["business_name"] = (business_name or "").strip()[:80]
    if telegram_channel is not None:
        cur["telegram_channel"] = (telegram_channel or "").strip()[:120]
    if support_phone is not None:
        cur["support_phone"] = (support_phone or "").strip()[:40]
    if support_telegram is not None:
        cur["support_telegram"] = (support_telegram or "").strip()[:80]
    if slogan is not None:
        cur["slogan"] = (slogan or "").strip()[:400] or DEFAULT_SLOGAN
    if pay_confirm_mode is not None:
        cur["pay_confirm_mode"] = normalize_pay_mode(pay_confirm_mode)
    if pay_suffix_digits is not None:
        try:
            cur["pay_suffix_digits"] = max(1, min(6, int(pay_suffix_digits)))
        except (TypeError, ValueError):
            cur["pay_suffix_digits"] = PAY_SUFFIX_DIGITS
    # Keep existing per-admin SMS token; create one if missing when enabling auto.
    sms_tok = (cur.get("sms_webhook_token") or "").strip()
    if not sms_tok and cur.get("pay_confirm_mode") == "auto":
        sms_tok = ensure_seller_sms_token(conn, admin_id)
        cur["sms_webhook_token"] = sms_tok
    digits = int(cur.get("pay_suffix_digits") or PAY_SUFFIX_DIGITS)
    digits = max(1, min(6, digits))
    cur["pay_suffix_digits"] = digits
    conn.execute(
        "INSERT INTO seller(admin_id, price, debt_toman, card_number, card_name, "
        "business_name, telegram_channel, support_phone, support_telegram, slogan, "
        "pay_confirm_mode, sms_webhook_token, pay_suffix_digits) "
        "VALUES (?,?,0,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(admin_id) DO UPDATE SET "
        "card_number=excluded.card_number, card_name=excluded.card_name, "
        "business_name=excluded.business_name, telegram_channel=excluded.telegram_channel, "
        "support_phone=excluded.support_phone, support_telegram=excluded.support_telegram, "
        "slogan=excluded.slogan, pay_confirm_mode=excluded.pay_confirm_mode, "
        "pay_suffix_digits=excluded.pay_suffix_digits, "
        "sms_webhook_token=CASE "
        "WHEN excluded.sms_webhook_token!='' THEN excluded.sms_webhook_token "
        "ELSE seller.sms_webhook_token END",
        (
            admin_id,
            2500,
            cur["card_number"],
            cur["card_name"],
            cur["business_name"],
            cur["telegram_channel"],
            cur["support_phone"],
            cur["support_telegram"],
            cur["slogan"],
            cur["pay_confirm_mode"],
            sms_tok,
            digits,
        ),
    )
    return get_seller_shop(conn, admin_id)


def set_seller_card(
    conn: sqlite3.Connection, admin_id: int, card_number: str, card_name: str
) -> dict:
    shop = set_seller_shop(
        conn, admin_id, card_number=card_number, card_name=card_name
    )
    return {"card_number": shop["card_number"], "card_name": shop["card_name"]}


def list_plans(
    conn: sqlite3.Connection, admin_id: int, *, active_only: bool = False
) -> list[dict]:
    sql = (
        "SELECT id, admin_id, title, gib, days, price_toman, user_count, active, fair_use, description, created_ts "
        "FROM pay_plan WHERE admin_id=?"
    )
    args: list = [admin_id]
    if active_only:
        sql += " AND active=1"
    sql += " ORDER BY price_toman, id"
    out = []
    for r in conn.execute(sql, args).fetchall():
        d = dict(r)
        d["user_count"] = max(1, int(d.get("user_count") or 1))
        d["fair_use"] = bool(int(d.get("fair_use") or 0))
        d["description"] = str(d.get("description") or "")
        out.append(d)
    return out


def add_plan(
    conn: sqlite3.Connection,
    *,
    admin_id: int,
    title: str,
    gib: float,
    days: int,
    price_toman: int,
    user_count: int = 1,
    description: str = "",
) -> dict:
    gib = float(gib)
    days = int(days)
    price = int(price_toman)
    users = max(1, min(1000, int(user_count or 1)))
    # gib == 0 → unlimited volume plan (only admin #1)
    if gib < 0 or gib > 100_000:
        raise ValueError("حجم پلن نامعتبر است.")
    if gib == 0 and int(admin_id) != UNLIMITED_ADMIN_ID:
        raise ValueError("فقط ادمین اصلی می‌تواند پلن نامحدود تعریف کند.")
    if days < 1 or days > 3650:
        raise ValueError("روز پلن نامعتبر است.")
    if price < 1000 or price > 500_000_000:
        raise ValueError("قیمت پلن نامعتبر است.")
    if gib == 0:
        title = (title or "").strip()[:80] or f"نامحدود / {days} روز"
    else:
        title = (title or "").strip()[:80] or f"{gib:g} گیگ / {days} روز"
    conn.execute(
        "INSERT INTO pay_plan(admin_id, title, gib, days, price_toman, user_count, active, created_ts, description) "
        "VALUES (?,?,?,?,?,?,1,?,?)",
        (int(admin_id), title, gib, days, price, users, time.time(), (description or "").strip()[:2000]),
    )
    rid = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    return dict(conn.execute("SELECT * FROM pay_plan WHERE id=?", (rid,)).fetchone())


def update_plan(
    conn: sqlite3.Connection,
    plan_id: int,
    *,
    admin_id: int | None = None,
    title: str | None = None,
    gib: float | None = None,
    days: int | None = None,
    price_toman: int | None = None,
    user_count: int | None = None,
    active: bool | None = None,
    fair_use: bool | None = None,
    description: str | None = None,
) -> dict:
    row = conn.execute("SELECT * FROM pay_plan WHERE id=?", (plan_id,)).fetchone()
    if not row:
        raise ValueError("پلن پیدا نشد.")
    if admin_id is not None and int(row["admin_id"]) != int(admin_id):
        raise ValueError("این پلن مال شما نیست.")
    title_v = str(row["title"] if title is None else (title or "").strip()[:80])
    gib_v = float(row["gib"] if gib is None else gib)
    days_v = int(row["days"] if days is None else days)
    price_v = int(row["price_toman"] if price_toman is None else price_toman)
    users_v = max(
        1,
        min(
            1000,
            int(row["user_count"] if user_count is None else user_count or 1),
        ),
    )
    active_v = int(row["active"] if active is None else (1 if active else 0))
    desc_v = str((row["description"] or "") if description is None else (description or "").strip()[:2000])
    fair_v = int((row["fair_use"] or 0) if fair_use is None else (1 if fair_use else 0))
    if gib_v < 0 or days_v < 1 or price_v < 1000:
        raise ValueError("مقادیر پلن نامعتبر است.")
    owner = int(row["admin_id"])
    if gib_v == 0 and owner != UNLIMITED_ADMIN_ID:
        raise ValueError("فقط ادمین اصلی می‌تواند پلن نامحدود داشته باشد.")
    conn.execute(
        "UPDATE pay_plan SET title=?, gib=?, days=?, price_toman=?, user_count=?, active=?, fair_use=?, description=? WHERE id=?",
        (title_v, gib_v, days_v, price_v, users_v, active_v, fair_v, desc_v, plan_id),
    )
    return dict(conn.execute("SELECT * FROM pay_plan WHERE id=?", (plan_id,)).fetchone())


def delete_plan(conn: sqlite3.Connection, plan_id: int, admin_id: int | None = None) -> None:
    row = conn.execute("SELECT admin_id FROM pay_plan WHERE id=?", (plan_id,)).fetchone()
    if not row:
        raise ValueError("پلن پیدا نشد.")
    if admin_id is not None and int(row["admin_id"]) != int(admin_id):
        raise ValueError("این پلن مال شما نیست.")
    conn.execute("DELETE FROM pay_plan WHERE id=?", (plan_id,))


def _pending_amounts(conn: sqlite3.Connection) -> set[int]:
    expire_orders(conn)
    rows = conn.execute(
        "SELECT pay_amount FROM pay_order WHERE status='pending'"
    ).fetchall()
    return {int(r["pay_amount"]) for r in rows}


def unique_order_amount(
    conn: sqlite3.Connection, price_toman: int, *, suffix_digits: int | None = None
) -> int:
    """Exact transfer amount: keep price stem, force unique N-digit suffix.

    With 3 digits, 25000 → 25001..25999 (not jumping to 30000 like 4-digit mode).
    """
    digits = int(suffix_digits if suffix_digits is not None else PAY_SUFFIX_DIGITS)
    digits = max(1, min(6, digits))
    price = max(1000, int(price_toman))
    mod = 10**digits
    used = _pending_amounts(conn)
    stem = price // mod
    for _ in range(400):
        suf = secrets.randbelow(mod - 1) + 1  # 1..(mod-1)
        amt = stem * mod + suf
        if amt < price:
            amt += mod
        if amt not in used:
            return amt
    # fallback: price + n
    for n in range(1, 20000):
        amt = price + n
        if amt not in used:
            return amt
    raise RuntimeError("نتوانستیم مبلغ یکتا بسازیم؛ دوباره تلاش کنید.")


def create_order(
    conn: sqlite3.Connection,
    *,
    admin_id: int,
    user_id: int,
    username: str,
    plan: dict,
    suffix_digits: int | None = None,
    ttl_sec: int | None = None,
) -> dict:
    expire_orders(conn)
    # One pending order per user at a time — replace by expiring old.
    conn.execute(
        "UPDATE pay_order SET status='expired', detail='سفارش جدید جایگزین شد' "
        "WHERE username=? AND status='pending'",
        (username,),
    )
    pay_amount = unique_order_amount(
        conn, int(plan["price_toman"]), suffix_digits=suffix_digits
    )
    now = time.time()
    ttl = int(ttl_sec) if ttl_sec is not None else ORDER_TTL_SEC
    ttl = max(60, min(24 * 3600, ttl))
    conn.execute(
        "INSERT INTO pay_order(admin_id, user_id, username, plan_id, gib, days, "
        "price_toman, pay_amount, status, ts, expires_ts, paid_ts, detail) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            int(admin_id),
            int(user_id),
            username,
            int(plan["id"]),
            float(plan["gib"]),
            int(plan["days"]),
            int(plan["price_toman"]),
            pay_amount,
            "pending",
            now,
            now + ttl,
            None,
            "",
        ),
    )
    rid = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    return dict(conn.execute("SELECT * FROM pay_order WHERE id=?", (rid,)).fetchone())


def get_order(conn: sqlite3.Connection, order_id: int) -> dict | None:
    expire_orders(conn)
    row = conn.execute("SELECT * FROM pay_order WHERE id=?", (order_id,)).fetchone()
    return dict(row) if row else None


def find_pending_by_amount(
    conn: sqlite3.Connection,
    amount_toman: int,
    *,
    admin_id: int | None = None,
) -> dict | None:
    expire_orders(conn)
    if admin_id is not None:
        row = conn.execute(
            "SELECT * FROM pay_order WHERE status='pending' AND pay_amount=? "
            "AND admin_id=? ORDER BY ts DESC LIMIT 1",
            (int(amount_toman), int(admin_id)),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM pay_order WHERE status='pending' AND pay_amount=? "
            "ORDER BY ts DESC LIMIT 1",
            (int(amount_toman),),
        ).fetchone()
    return dict(row) if row else None


def pending_for_username(conn: sqlite3.Connection, username: str) -> dict | None:
    expire_orders(conn)
    row = conn.execute(
        "SELECT * FROM pay_order WHERE username=? AND status='pending' "
        "ORDER BY ts DESC LIMIT 1",
        (username,),
    ).fetchone()
    return dict(row) if row else None


def list_pending_orders(
    conn: sqlite3.Connection, admin_id: int, *, limit: int = 40
) -> list[dict]:
    expire_orders(conn)
    rows = conn.execute(
        "SELECT * FROM pay_order WHERE admin_id=? AND status='pending' "
        "ORDER BY ts DESC LIMIT ?",
        (int(admin_id), max(1, min(100, int(limit)))),
    ).fetchall()
    return [dict(r) for r in rows]


def reject_order(
    conn: sqlite3.Connection, order_id: int, *, admin_id: int | None = None
) -> dict:
    row = conn.execute("SELECT * FROM pay_order WHERE id=?", (order_id,)).fetchone()
    if not row:
        raise ValueError("سفارش پیدا نشد.")
    order = dict(row)
    if admin_id is not None and int(order["admin_id"]) != int(admin_id):
        raise ValueError("این سفارش مال شما نیست.")
    if order["status"] != "pending":
        raise ValueError("فقط سفارش در انتظار قابل رد است.")
    conn.execute(
        "UPDATE pay_order SET status='rejected', detail=?, paid_ts=? WHERE id=?",
        ("رد شده توسط ادمین", time.time(), order_id),
    )
    return dict(conn.execute("SELECT * FROM pay_order WHERE id=?", (order_id,)).fetchone())


def _panel_request(method: str, path: str, body: dict | None = None) -> dict:
    import subprocess

    key = panel_api_key()
    if not key:
        raise RuntimeError("PANEL_API_KEY در secrets تنظیم نشده است.")
    base = _panel_base()
    url = base.rstrip("/") + path
    cmd = [
        "curl",
        "-4",
        "-sS",
        "--max-time",
        "25",
        "-X",
        method.upper(),
        "-H",
        f"X-API-Key: {key}",
        "-H",
        "Accept: application/json",
        "-H",
        "User-Agent: settle-web/pay",
        "-w",
        "\n__HTTP__%{http_code}",
    ]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "--data-binary", json.dumps(body, ensure_ascii=False)]
    cmd.append(url)
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception as e:
        raise RuntimeError(f"خطای تماس با پنل: {e}") from e
    raw = (cp.stdout or "")
    if "__HTTP__" in raw:
        body_txt, _, code_txt = raw.rpartition("__HTTP__")
    else:
        body_txt, code_txt = raw, "0"
    code = int(code_txt.strip() or "0")
    if cp.returncode != 0 and not body_txt.strip():
        err = (cp.stderr or "").strip()[:300]
        raise RuntimeError(f"خطای تماس با پنل: {err or cp.returncode}")
    if code >= 400:
        raise RuntimeError(f"خطای پنل ({code}): {body_txt.strip()[:400]}")
    return json.loads(body_txt) if body_txt.strip() else {}


def fetch_panel_user(username: str) -> dict:
    uname = urllib.parse.quote(username, safe="")
    return _panel_request("GET", f"/api/user/{uname}")


def reset_user_usage(username: str) -> dict:
    """Zero used_traffic via panel reset endpoint (PasarGuard/Marzban-compatible)."""
    uname = urllib.parse.quote(username, safe="")
    # Prefer username route; fall back to by-id if needed.
    try:
        return _panel_request("POST", f"/api/user/{uname}/reset")
    except RuntimeError as e:
        msg = str(e)
        if "404" not in msg and "405" not in msg:
            raise
        user = fetch_panel_user(username)
        uid = user.get("id")
        if not uid:
            raise RuntimeError("ریست مصرف ناموفق بود و id کاربر پیدا نشد.") from e
        return _panel_request("POST", f"/api/user/by-id/{int(uid)}/reset")


def apply_topup(username: str, gib: float, days: int) -> dict:
    """Renew pack: set data_limit to purchased size, reset used_traffic to 0, extend expire.

    Previous ceiling/usage does not carry into the new period.
    gib <= 0 means unlimited volume (panel data_limit = 0).
    """
    user = fetch_panel_user(username)
    cur_limit = int(user.get("data_limit") or 0)
    old_used = int(user.get("used_traffic") or 0)
    gib_f = float(gib)
    if gib_f <= 0:
        new_limit = 0
        pack_bytes = 0
    else:
        pack_bytes = int(round(gib_f * GIB))
        if pack_bytes < 1:
            raise ValueError("حجم شارژ نامعتبر است.")
        new_limit = pack_bytes

    now = int(time.time())
    cur_exp = user.get("expire")
    if cur_exp is None or cur_exp == "" or cur_exp == 0:
        base = now
    else:
        try:
            if isinstance(cur_exp, str) and "T" in cur_exp:
                # ISO datetime from API
                from datetime import datetime

                base = int(datetime.fromisoformat(cur_exp.replace("Z", "+00:00")).timestamp())
            else:
                base = int(cur_exp)
        except (TypeError, ValueError):
            base = now
    if base < now:
        base = now
    new_exp = base + int(days) * 86400

    uname = urllib.parse.quote(username, safe="")
    # Reset usage first so old traffic does not count against the new pack.
    reset_user_usage(username)
    body = {
        "data_limit": new_limit,
        "expire": new_exp,
        "status": "active",
    }
    updated = _panel_request("PUT", f"/api/user/{uname}", body)
    return {
        "username": username,
        "old_limit": cur_limit,
        "new_limit": int(updated.get("data_limit") or new_limit),
        "old_used": old_used,
        "old_expire": cur_exp,
        "new_expire": updated.get("expire") or new_exp,
        "add_bytes": pack_bytes,
        "days": int(days),
        "usage_reset": True,
    }


def fulfill_order(
    conn: sqlite3.Connection,
    order_id: int,
    *,
    apply: Callable[[str, float, int], dict] | None = None,
) -> dict:
    row = conn.execute("SELECT * FROM pay_order WHERE id=?", (order_id,)).fetchone()
    if not row:
        raise ValueError("سفارش پیدا نشد.")
    order = dict(row)
    if order["status"] == "paid":
        return order
    if order["status"] != "pending":
        raise ValueError(f"وضعیت سفارش قابل شارژ نیست: {order['status']}")
    if float(order["expires_ts"]) < time.time():
        conn.execute(
            "UPDATE pay_order SET status='expired', detail=? WHERE id=?",
            ("مهلت پرداخت تمام شد", order_id),
        )
        raise ValueError("مهلت پرداخت این سفارش تمام شده است.")

    fn = apply or apply_topup
    try:
        result = fn(str(order["username"]), float(order["gib"]), int(order["days"]))
    except Exception as e:  # noqa: BLE001
        conn.execute(
            "UPDATE pay_order SET detail=? WHERE id=?",
            (f"خطا در اعمال شارژ: {e}"[:400], order_id),
        )
        raise

    detail = (
        f"تمدید شد · سقف {result.get('old_limit')}→{result.get('new_limit')} "
        f"(مصرف قبلی ریست) · {order['gib']}GiB / {order['days']}d"
    )
    now = time.time()
    conn.execute(
        "UPDATE pay_order SET status='paid', paid_ts=?, detail=? WHERE id=?",
        (now, detail[:400], order_id),
    )
    if result.get("usage_reset") and order.get("user_id"):
        # Renewal = full new pack: re-bill whole limit in the settlement ledger.
        conn.execute(
            "INSERT INTO ledger(admin_id, user_id, billed_bytes) VALUES(?,?,0) "
            "ON CONFLICT(admin_id, user_id) DO UPDATE SET billed_bytes=0",
            (int(order["admin_id"]), int(order["user_id"])),
        )
    out = dict(conn.execute("SELECT * FROM pay_order WHERE id=?", (order_id,)).fetchone())
    out["apply"] = result
    return out


def toman_candidates_from_sms(raw_amount: int) -> list[int]:
    """Possible toman interpretations of a bank SMS amount."""
    raw = int(raw_amount)
    out: list[int] = []
    if raw % 10 == 0:
        out.append(raw // 10)
    out.append(raw)
    # unique preserve order
    seen: set[int] = set()
    uniq: list[int] = []
    for a in out:
        if a not in seen:
            seen.add(a)
            uniq.append(a)
    return uniq
