"""Opt-in SNI observation from an Xray access log (product requirement: kept in scope).

Default Shahrah nodes write ``access: none``. Enabling ``NodeState.access_log`` turns logging
on; this module then tails those lines and aggregates destination hostnames per user label
(``email:`` in Xray terms). It never MITMs traffic.

Design choices vs the old standalone tool:

* no hardcoded server IPs or panel URLs;
* retention is mandatory (default 48h) so a seized disk does not hold unbounded history;
* aggregate and recent-hit views are both available; the ops console can show either;
* watchlists (e.g. adult domains) are loaded from an operator-supplied file, never shipped.
"""

from __future__ import annotations

import contextlib
import re
import time
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .models import ConfigError

ACCESS_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?"
    r".*?accepted (?P<net>tcp|udp):(?P<dest>\[[^\]]+\]|[^:\s]+):(?P<port>\d+)"
    r".*?(?:email: (?P<email>\S+))?\s*$"
)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass(frozen=True, slots=True)
class AccessHit:
    when: float  # unix seconds (parsed from the log timestamp when possible, else ingest time)
    user: str
    domain: str
    port: int
    net: str


def parse_access_line(line: str, *, now: float | None = None) -> AccessHit | None:
    match = ACCESS_RE.search(line.strip())
    if not match:
        return None
    user = (match.group("email") or "").strip().rstrip(",").lower()
    dest = (match.group("dest") or "").strip().strip("[]").lower().rstrip(".")
    if not user or not dest:
        return None
    if _IPV4_RE.match(dest) or dest.count(":") >= 2:
        return None
    when = now if now is not None else time.time()
    with contextlib.suppress(ValueError):
        when = time.mktime(time.strptime(match.group("ts"), "%Y/%m/%d %H:%M:%S"))
    return AccessHit(when, user, dest, int(match.group("port")), match.group("net"))


def load_watchlist(path: Path) -> frozenset[str]:
    if not path.exists():
        raise ConfigError(f"watchlist not found: {path}")
    names: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        item = line.strip().lower().rstrip(".")
        if item and not item.startswith("#"):
            names.add(item)
    return frozenset(names)


def domain_matches(host: str, watchlist: frozenset[str]) -> bool:
    host = host.lower().rstrip(".")
    if not host or _IPV4_RE.match(host):
        return False
    parts = host.split(".")
    return any(".".join(parts[index:]) in watchlist for index in range(len(parts) - 1))


@dataclass
class WatchStore:
    retention_s: float = 48 * 3600
    hits: list[AccessHit] = field(default_factory=list)

    def ingest(self, lines: Iterable[str], *, now: float | None = None) -> int:
        added = 0
        stamp = time.time() if now is None else now
        for line in lines:
            hit = parse_access_line(line, now=stamp)
            if hit is None:
                continue
            self.hits.append(hit)
            added += 1
        self.expire(now=stamp)
        return added

    def ingest_file(self, path: Path, *, now: float | None = None) -> int:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ConfigError(f"cannot read access log: {exc}") from exc
        return self.ingest(text.splitlines(), now=now)

    def expire(self, *, now: float | None = None) -> None:
        stamp = time.time() if now is None else now
        cutoff = stamp - self.retention_s
        self.hits = [hit for hit in self.hits if hit.when >= cutoff]

    def by_user(self, *, watchlist: frozenset[str] | None = None) -> dict[str, Counter[str]]:
        out: dict[str, Counter[str]] = defaultdict(Counter)
        for hit in self.hits:
            if watchlist is not None and not domain_matches(hit.domain, watchlist):
                continue
            out[hit.user][hit.domain] += 1
        return dict(out)

    def summary(self, *, watchlist: frozenset[str] | None = None) -> dict[str, object]:
        per_user = self.by_user(watchlist=watchlist)
        return {
            "users": len(per_user),
            "hits": sum(sum(counter.values()) for counter in per_user.values()),
            "by_user": {user: dict(counter.most_common(50)) for user, counter in per_user.items()},
        }


def follow_new_lines(path: Path, *, start_at_end: bool = True) -> Iterator[str]:
    """Yield new lines appended to ``path`` (blocking). Used by a long-running watch service."""
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        if start_at_end:
            handle.seek(0, 2)
        while True:
            line = handle.readline()
            if line:
                yield line
            else:
                time.sleep(0.5)
