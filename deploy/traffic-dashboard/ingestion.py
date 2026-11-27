"""Durable, per-host authenticated snapshot ingestion."""
import hashlib
import hmac
import re
import sqlite3
import time
import uuid


def initialize(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS hosts(
            id TEXT PRIMARY KEY, label TEXT NOT NULL, token_hash TEXT NOT NULL,
            last_delivery_ns INTEGER);
        CREATE TABLE IF NOT EXISTS snapshots(
            host TEXT NOT NULL REFERENCES hosts(id), captured_ns INTEGER NOT NULL,
            boot_id TEXT NOT NULL, interface TEXT NOT NULL, ifindex INTEGER NOT NULL,
            rx TEXT NOT NULL, tx TEXT NOT NULL, PRIMARY KEY(host, captured_ns));
    """)


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def accept(conn, token, batch, now_ns=None):
    """Commit before acknowledging. Conflicting replays roll back the whole batch."""
    now = time.time_ns() if now_ns is None else now_ns
    host = batch.get("server")
    if not isinstance(host, str) or not isinstance(token, str) or not token:
        raise PermissionError()
    row = conn.execute("SELECT token_hash FROM hosts WHERE id=?", (host,)).fetchone()
    if row is None or not hmac.compare_digest(row[0], token_hash(token)):
        raise PermissionError()
    samples = batch.get("samples")
    if not isinstance(samples, list) or not 1 <= len(samples) <= 512:
        raise ValueError("Invalid batch size")
    accepted = []
    with conn:
        for sample in samples:
            if not isinstance(sample, dict):
                raise ValueError("Invalid snapshot")
            stamp = sample.get("captured_ns")
            if type(stamp) is not int or not 0 < stamp <= now + 300_000_000_000:
                raise ValueError("Invalid timestamp")
            index = sample.get("ifindex")
            iface = sample.get("interface")
            if type(index) is not int or not 1 <= index <= 2**31-1:
                raise ValueError("Invalid interface index")
            if not isinstance(iface, str) or not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,14}", iface):
                raise ValueError("Invalid interface")
            boot = str(uuid.UUID(str(sample.get("boot_id"))))
            counters = []
            for field in ("rx","tx"):
                value = sample.get(field)
                if not isinstance(value,str) or not re.fullmatch(r"[0-9]{1,20}",value) or int(value)>=2**64:
                    raise ValueError("Invalid byte counter")
                counters.append(str(int(value)))
            values = (boot, iface, index, *counters)
            cur = conn.execute(
                "INSERT INTO snapshots VALUES(?,?,?,?,?,?,?) ON CONFLICT(host,captured_ns) DO NOTHING",
                (host, stamp, *values))
            if not cur.rowcount:
                stored = conn.execute(
                    "SELECT boot_id,interface,ifindex,rx,tx FROM snapshots WHERE host=? AND captured_ns=?",
                    (host,stamp)).fetchone()
                if tuple(stored) != values:
                    raise ValueError("Conflicting snapshot")
            accepted.append(stamp)
        conn.execute("UPDATE hosts SET last_delivery_ns=? WHERE id=?", (now,host))
    return {"server": host, "accepted": accepted}
