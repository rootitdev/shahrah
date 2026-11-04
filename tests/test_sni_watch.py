from __future__ import annotations

import json
import time
from dataclasses import replace
from pathlib import Path

from shahrah.cli import main
from shahrah.sni_watch import WatchStore, domain_matches, load_watchlist, parse_access_line


def _line(user: str = "alice", domain: str = "instagram.com") -> str:
    ts = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())
    return f"{ts}.123456 from 198.51.100.1:1 accepted tcp:{domain}:443 email: {user}"


LINE = _line()


def test_parse_access_line_extracts_user_and_domain() -> None:
    hit = parse_access_line(LINE)
    assert hit is not None
    assert hit.user == "alice" and hit.domain == "instagram.com" and hit.port == 443


def test_skips_ip_destinations_and_lines_without_email() -> None:
    ts = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())
    assert parse_access_line(f"{ts} accepted tcp:198.51.100.9:443 email: a") is None
    assert parse_access_line(f"{ts} accepted tcp:example.com:443") is None


def test_store_aggregates_and_expires(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text(_line() + "\n" + _line("bob", "t.me") + "\n", encoding="utf-8")
    store = WatchStore(retention_s=3600)
    assert store.ingest_file(log) == 2
    summary = store.summary()
    assert summary["users"] == 2
    assert summary["by_user"]["alice"]["instagram.com"] == 1
    store.hits[0] = replace(store.hits[0], when=store.hits[0].when - 10_000)
    store.expire(now=store.hits[1].when)
    assert "alice" not in store.by_user()


def test_watchlist_suffix_match(tmp_path: Path) -> None:
    path = tmp_path / "list.txt"
    path.write_text("example.com\n", encoding="utf-8")
    watchlist = load_watchlist(path)
    assert domain_matches("www.example.com", watchlist)
    assert not domain_matches("example.org", watchlist)


def test_cli_sni_watch(tmp_path: Path, capsys) -> None:
    log = tmp_path / "a.log"
    log.write_text(_line() + "\n", encoding="utf-8")
    assert main(["sni-watch", "--log", str(log)]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["by_user"]["alice"]["instagram.com"] == 1
