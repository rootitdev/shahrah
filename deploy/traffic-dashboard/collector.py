"""Capture one interface snapshot into a durable SQLite outbox."""
import argparse
import re
import sqlite3
import time
from contextlib import closing
from pathlib import Path


def capture(database, interface, *, sysnet=Path("/sys/class/net"),
            boot_file=Path("/proc/sys/kernel/random/boot_id"), now=time.time_ns):
    with closing(sqlite3.connect(database)) as db:
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='agent_setting'").fetchone():
            row = db.execute("SELECT value FROM agent_setting WHERE key='interface'").fetchone()
            if row:
                proposed=row[0]
                if re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,14}",proposed) and (sysnet/proposed/"ifindex").is_file():
                    interface=proposed
    if not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,14}", interface):
        raise ValueError("Invalid interface name")
    device = sysnet / interface
    stamp = now()
    boot = boot_file.read_text().strip()
    index = int((device / "ifindex").read_text())
    rx, tx = (int((device / "statistics" / name).read_text())
              for name in ("rx_bytes", "tx_bytes"))
    with closing(sqlite3.connect(database)) as db, db:
        db.execute("""CREATE TABLE IF NOT EXISTS samples (
            captured_ns INTEGER PRIMARY KEY, boot_id TEXT NOT NULL,
            interface TEXT NOT NULL, ifindex INTEGER NOT NULL,
            rx TEXT NOT NULL, tx TEXT NOT NULL)""")
        db.execute("INSERT INTO samples VALUES (?, ?, ?, ?, ?, ?)",
                   (stamp, boot, interface, index, str(rx), str(tx)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--interface", required=True)
    args = parser.parse_args()
    capture(args.database, args.interface)
