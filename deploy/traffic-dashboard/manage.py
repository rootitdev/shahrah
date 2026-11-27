"""Local administration of the Shahrah traffic dashboard."""
import argparse
from contextlib import closing
from datetime import datetime
from getpass import getpass
import os
from pathlib import Path
import secrets
import sqlite3

from dashboard import configure, password_hash
from ingestion import token_hash
from reporting import TEHRAN, month_start

INVENTORY = {
    "master": ("مستر آلمان", "shared", 1000, 322, "hourly", 3151),
    "nl": ("خروجی هلند", "shared", 1000, 322, "hourly", 3151),
    "ir": ("ایران", "download", 1000, 1084, "hourly", 2342),
    "netcup": ("نت‌کاپ آلمان", "free", 0, 0, "monthly", 3000000),
}


def register(db, host, target):
    token = secrets.token_urlsafe(36)
    label, direction, allowance, rate, mode, rent = INVENTORY[host]
    # Refuse accidental replacement of an existing live identity.
    if db.execute("SELECT 1 FROM hosts WHERE id=?", (host,)).fetchone():
        raise ValueError("Host already provisioned")
    with target.open("x", encoding="ascii") as out:
        out.write(token)
    try:
        with db:
            db.execute("INSERT INTO hosts(id,label,token_hash) VALUES(?,?,?)",
                       (host,label,token_hash(token)))
            effective = month_start(datetime.now(TEHRAN).date()).isoformat()
            db.execute("""INSERT INTO tariffs(host,effective,direction,allowance,rate,
                           mode,rent,unit,calendar,reset) VALUES(?,?,?,?,?,?,?,1000000000,'jalali',1)""",
                       (host,effective,direction,allowance,rate,mode,rent))
    except Exception:
        target.unlink()
        raise


def backup(source, target):
    """SQLite online backup; reserve destination exclusively and validate it."""
    with target.open("xb"):
        pass
    try:
        with closing(sqlite3.connect(source.resolve().as_uri()+"?mode=ro",uri=True)) as original:
            with closing(sqlite3.connect(target)) as dest:
                original.backup(dest)
                if dest.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("Invalid SQLite backup")
                if not dest.execute("SELECT 1 FROM sqlite_master WHERE name='hosts'").fetchone():
                    raise ValueError("Not a traffic database")
    except Exception:
        target.unlink()
        raise


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser()
    parser.add_argument("--db",required=True,type=Path)
    sub=parser.add_subparsers(dest="command",required=True)
    auth=sub.add_parser("password")
    auth.add_argument("--name",default="admin")
    agent=sub.add_parser("register")
    agent.add_argument("host",choices=INVENTORY)
    agent.add_argument("token_file",type=Path)
    for command in ("backup","restore"):
        sub.add_parser(command).add_argument("file",type=Path)
    args=parser.parse_args()
    if args.command=="backup":
        return backup(args.db,args.file)
    if args.command=="restore":
        return backup(args.file,args.db)
    with closing(sqlite3.connect(args.db)) as db:
        configure(db)
        if args.command=="register":
            return register(db,args.host,args.token_file)
        secret=getpass("New password (at least 14 characters): ")
        if len(secret)<14 or secret!=getpass("Confirm: "):
            raise ValueError("Passwords differ or are too short")
        salt=secrets.token_bytes(16)
        with db:
            db.execute("DELETE FROM operator")
            db.execute("INSERT INTO operator VALUES(?,?,?)",(args.name,salt,password_hash(secret,salt)))
            db.execute("DELETE FROM sessions")
            db.execute("DELETE FROM attempts")


if __name__=="__main__":
    main()
