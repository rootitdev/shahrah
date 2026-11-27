"""Loopback HTTP entry point. Caddy provides the public HTTPS connection."""
import argparse
import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import time
from contextlib import closing
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from settings import initialize_settings, save, settings, snapshot_csv
from views import overview
from reporting import jalali_to_gregorian
from ingestion import accept, initialize, token_hash


def configure(db):
    initialize(db)
    initialize_settings(db)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS tariffs(
            host TEXT NOT NULL, effective TEXT NOT NULL, direction TEXT NOT NULL,
            allowance INTEGER NOT NULL, rate INTEGER NOT NULL, mode TEXT NOT NULL,
            rent INTEGER NOT NULL, unit INTEGER NOT NULL, calendar TEXT NOT NULL,
            reset INTEGER NOT NULL, PRIMARY KEY(host,effective));
        CREATE TABLE IF NOT EXISTS operator(name TEXT PRIMARY KEY, salt BLOB, verifier BLOB);
        CREATE TABLE IF NOT EXISTS sessions(digest TEXT PRIMARY KEY, expires INTEGER);
        CREATE TABLE IF NOT EXISTS attempts(ts INTEGER NOT NULL);
    """)


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(),salt=salt,n=32768,r=8,p=1,maxmem=64000000)


def document(title, content):
    return f"""<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>
<style>@import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap');
:root{{--bg:#0b1220;--surface:#121c2d;--surface2:#18263a;--line:#2b3a52;--text:#e6edf7;--muted:#9eacc0;--accent:#38bdf8}}
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;background:radial-gradient(circle at 85% 0,#1a3550 0,transparent 34rem),var(--bg);color:var(--text);font:15px/1.9 Vazirmatn,Tahoma,sans-serif}}
main{{width:min(1120px,calc(100% - 32px));margin:32px auto;padding:28px;background:rgba(18,28,45,.94);border:1px solid var(--line);border-radius:22px;box-shadow:0 24px 70px #0005}} h1{{margin:0 0 14px;font-size:clamp(1.35rem,3vw,2rem)}}
nav{{display:flex;gap:12px;flex-wrap:wrap;margin:0 0 20px;padding-bottom:14px;border-bottom:1px solid var(--line)}} a{{color:var(--accent);text-underline-offset:4px}}p{{margin:8px 0;color:var(--muted)}}
section{{margin:16px 0;padding:20px;background:var(--surface);border:1px solid var(--line);border-radius:16px;overflow:hidden}} h2{{margin:0 0 10px;font-size:1.2rem}}details{{margin-top:14px;border-top:1px solid var(--line);padding-top:12px}}summary{{cursor:pointer;color:#dbeafe;font-weight:600}}
table{{width:100%;border-collapse:separate;border-spacing:0;margin-top:10px;border:1px solid var(--line);border-radius:12px;overflow:hidden}}th,td{{padding:10px 12px;text-align:right;border-bottom:1px solid var(--line)}}th{{background:var(--surface2);color:#dbeafe}}tr:last-child td{{border-bottom:0}}
form{{display:grid;gap:10px;max-width:620px;margin:12px 0}}label{{display:grid;gap:5px;color:#dbeafe;font-weight:500}}input,select,button{{font:inherit;border-radius:10px;padding:9px 12px;border:1px solid var(--line)}}input,select{{width:100%;background:#0d1728;color:var(--text)}}button{{width:max-content;color:#06121d;background:var(--accent);border:0;font-weight:700;cursor:pointer}}
@media(max-width:640px){{main{{width:calc(100% - 20px);margin:10px auto;padding:16px;border-radius:16px}}section{{padding:14px;margin:12px 0}}table{{font-size:13px}}th,td{{padding:8px}}}}
</style>
<main><h1>{title}</h1>{content}</main></html>""".encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):
        pass

    def reply(self,code,body=b"",kind="text/html; charset=utf-8",headers=()):
        self.send_response(code)
        for key,value in headers:
            self.send_header(key,value)
        self.send_header("Content-Type",kind)
        self.send_header("Cache-Control","no-store")
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src https://static.cloudflareinsights.com; img-src 'self' data:; connect-src https://cloudflareinsights.com https://*.cloudflareinsights.com; form-action 'self'; frame-ancestors 'none'")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def session(self,db):
        cookie=SimpleCookie()
        cookie.load(self.headers.get("Cookie",""))
        value=cookie.get("__Host-dashboard")
        digest=token_hash(value.value) if value else ""
        return digest if db.execute("SELECT 1 FROM sessions WHERE digest=? AND expires>?",(digest,time.time())).fetchone() else None

    def do_GET(self):
        path=urlsplit(self.path).path
        if path == "/favicon.ico":
            return self.reply(200, b"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='8' fill='#38bdf8'/><path d='M8 17h16M16 8v16' stroke='#0b1220' stroke-width='4'/></svg>", "image/svg+xml")
        if path not in ("/", "/settings", "/export"):
            return self.reply(404)
        with closing(sqlite3.connect(self.server.database)) as db:
            if not self.session(db):
                return self.reply(200,document("ورود به پنل شاهراه",'<form method="post" action="/login"><label>نام کاربری<input name="username" required autocomplete="username"></label><label>رمز عبور<input name="password" type="password" required autocomplete="current-password"></label><button>ورود</button></form>'))
            if path=="/settings":
                return self.reply(200,document("تنظیمات و ثبت مالی",settings(db)))
            if path=="/export":
                return self.reply(200,snapshot_csv(db),"text/csv; charset=utf-8",
                                  [("Content-Disposition",'attachment; filename="traffic.csv"')])
            try:
                query=parse_qs(urlsplit(self.path).query,max_num_fields=6)
                end_value=query.get("end",[None])[0]
                end=jalali_to_gregorian(end_value).isoformat() if end_value else None
                content='<nav><a href="/settings">تنظیمات و ثبت مالی</a></nav>'+overview(
                    db,end,migrated=int(query.get("migrated",["100"])[0]),
                    retained_rent=int(query.get("retained",["0"])[0]))
            except ValueError:
                return self.reply(400,document("تاریخ نامعتبر", '<a href="/">بازگشت</a>'))
            return self.reply(200,document("مصرف و هزینهٔ سرورها",content+
                '<form method="post" action="/logout"><button>خروج</button></form>'))

    def do_POST(self):
        try:
            length=int(self.headers.get("Content-Length","0"))
            if not 0<length<=200000 and self.path!="/logout":
                return self.reply(413)
            if not 0<=length<=200000:
                return self.reply(413)
            data=self.rfile.read(length)
            with closing(sqlite3.connect(self.server.database,timeout=10)) as db:
                if self.path=="/api/ingest":
                    auth=self.headers.get("Authorization","")
                    if not auth.startswith("Bearer "):
                        return self.reply(401)
                    batch=json.loads(data)
                    if not isinstance(batch,dict):
                        return self.reply(400)
                    result=accept(db,auth[7:],batch)
                    if batch.get("interface_settings") is True:
                        interface=db.execute("SELECT name FROM agent_interfaces WHERE host=?", (result["server"],)).fetchone()
                        if interface:
                            result["interface"]=interface[0]
                    return self.reply(200,json.dumps(result).encode(),"application/json")
                if self.headers.get("Origin") not in (None,"https://traffic.argosatra.ir"):
                    return self.reply(403)
                if self.path=="/settings":
                    if not self.session(db):
                        return self.reply(403)
                    form={k:v[0] for k,v in parse_qs(data.decode(),max_num_fields=20).items()}
                    try:
                        save(db,form,db.execute("SELECT name FROM operator").fetchone()[0])
                    except (KeyError,ValueError):
                        return self.reply(400,document("اطلاعات ثبت نشد","تاریخ، مقدار و توضیح را بررسی کنید. مصرف دستی باید پیش از اولین نمونه باشد."))
                    return self.reply(303,headers=[("Location","/settings")])
                if self.path=="/logout":
                    with db:
                        db.execute("DELETE FROM sessions WHERE digest=?",(self.session(db),))
                    return self.reply(303,headers=[("Location","/")])
                if self.path!="/login":
                    return self.reply(404)
                form=parse_qs(data.decode(),max_num_fields=2)
                now=int(time.time())
                with db:
                    db.execute("DELETE FROM attempts WHERE ts<?",(now-300,))
                    if db.execute("SELECT count(*) FROM attempts").fetchone()[0]>=15:
                        return self.reply(429)
                    db.execute("INSERT INTO attempts VALUES(?)",(now,))
                row=db.execute("SELECT salt,verifier FROM operator WHERE name=?",(form.get("username",[""])[0],)).fetchone()
                computed=password_hash(form.get("password",[""])[0],row[0] if row else bytes(16))
                if not row or not hmac.compare_digest(computed,row[1]):
                    return self.reply(403,document("ورود ناموفق",'<a href="/">تلاش دوباره</a>'))
                token=secrets.token_urlsafe(32)
                with db:
                    db.execute("DELETE FROM sessions WHERE expires<=?",(now,))
                    db.execute("INSERT INTO sessions VALUES(?,?)",(token_hash(token),now+28800))
                self.reply(303,headers=[("Location","/"),("Set-Cookie",f"__Host-dashboard={token}; Secure; HttpOnly; SameSite=Strict; Path=/")])
        except PermissionError:
            self.reply(401)
        except (ValueError,TypeError,UnicodeError):
            self.reply(400)


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--db",required=True)
    parser.add_argument("--port",type=int,default=8795)
    args=parser.parse_args()
    os.umask(0o077)
    with closing(sqlite3.connect(args.db)) as db:
        configure(db)
    server=ThreadingHTTPServer(("127.0.0.1",args.port),Handler)
    server.database=args.db
    server.serve_forever()
