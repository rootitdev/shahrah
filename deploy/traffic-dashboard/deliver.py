"""Deliver queued traffic snapshots to the Shahrah dashboard."""
import argparse
import json
import sqlite3
import urllib.request
from contextlib import closing
from pathlib import Path


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def deliver(database, server, token, *, send=None):
    if send is None:
        send = urllib.request.build_opener(NoRedirect()).open
    with closing(sqlite3.connect(database)) as db:
        db.row_factory = sqlite3.Row
        # A fixed boundary keeps concurrently collected samples for tomorrow.
        boundary = db.execute("SELECT MAX(captured_ns) FROM samples").fetchone()[0]
        while boundary is not None:
            rows = db.execute(
                "SELECT * FROM samples WHERE captured_ns <= ? ORDER BY captured_ns LIMIT 512",
                (boundary,),
            ).fetchall()
            if not rows:
                break
            data = {"server": server, "samples": [dict(row) for row in rows]}
            request = urllib.request.Request(
                "https://traffic.argosatra.ir/api/ingest",
                data=json.dumps(data).encode(),
                headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                         "User-Agent": "Shahrah-Traffic-Agent/1.0"},
            )
            with send(request, timeout=30) as response:
                ack = json.load(response)
            stamps = [row["captured_ns"] for row in rows]
            if ack != {"server": server, "accepted": stamps}:
                raise ValueError("Batch acknowledgement does not match the submitted samples")
            with db:
                db.executemany("DELETE FROM samples WHERE captured_ns = ?", [(s,) for s in stamps])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--server", required=True)
    parser.add_argument("--token-file", required=True, type=Path)
    args = parser.parse_args()
    deliver(args.database, args.server, args.token_file.read_text().strip())
