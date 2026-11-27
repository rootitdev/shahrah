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
<style>*{{box-sizing:border-box}}body{{margin:auto;max-width:980px;padding:24px;background:#f6f5ef;color:#172d32;font:16px/1.8 Tahoma,sans-serif}}
h1{{font-size:1.6rem}}main{{padding:20px;background:white;border:1px solid #ddd;border-radius:12px}}
section{{overflow-x:auto}}table{{width:100%;border-collapse:collapse}}td,th{{padding:10px;text-align:right;border-bottom:1px solid #ddd}}
input,button{{font:inherit;padding:6px 12px;margin:4px}}label{{display:block}}button{{color:white;background:#155951;border:0;border-radius:6px}}</style>
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
        self.send_header("Content-Security-Policy","default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
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
                end=parse_qs(urlsplit(self.path).query).get("end",[None])[0]
                content='<nav><a href="/settings">تنظیمات و ثبت مالی</a></nav>'+overview(db,end)
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
