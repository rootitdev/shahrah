"""Exchange of probe results between vantage points.

The control vantage (a free network) publishes a small JSON report; the field vantage reads it.
How the file travels (static HTTPS, scp, a shared bucket) is the operator's choice. The report
contains only endpoint names and booleans, never addresses or secrets.

    {"version": 1, "vantage": "control", "generated_at": 1700000000.0,
     "results": {"exit-a": true, "exit-b": false}}

A report older than ``max_age_s`` is ignored: a stale "ok" must never veto a burn decision,
and a stale "fail" must never cause one.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from .prober import ProbeResult

log = logging.getLogger("shahrah.vantage")

REPORT_VERSION = 1
MAX_REPORT_BYTES = 64 * 1024
Clock = Callable[[], float]


class VantageError(Exception):
    """A report could not be read or is malformed."""


def build_report(
    results: Sequence[ProbeResult], *, vantage: str = "control", now: float | None = None
) -> dict[str, object]:
    return {
        "version": REPORT_VERSION,
        "vantage": vantage,
        "generated_at": time.time() if now is None else now,
        "results": {r.endpoint: bool(r.ok) for r in results},
    }


def parse_report(text: str, *, now: float, max_age_s: float) -> dict[str, bool]:
    """Return the results of a fresh, well-formed report; raise ``VantageError`` otherwise."""
    try:
        data = json.loads(text)
        if data["version"] != REPORT_VERSION:
            raise VantageError(f"unsupported report version {data['version']!r}")
        generated_at = float(data["generated_at"])
        results = data["results"]
    except (KeyError, TypeError, ValueError) as exc:
        raise VantageError(f"malformed report: {exc}") from exc
    if not isinstance(results, dict) or not all(
        isinstance(k, str) and isinstance(v, bool) for k, v in results.items()
    ):
        raise VantageError("report results must map names to booleans")
    age = now - generated_at
    if age > max_age_s:
        raise VantageError(f"report is stale ({age:.0f}s old, limit {max_age_s:.0f}s)")
    if age < -max_age_s:
        raise VantageError("report timestamp is in the future")
    return dict(results)


def write_report(path: Path, report: Mapping[str, object]) -> None:
    """Atomically replace ``path`` so a reader never sees a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".report-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(report, handle, sort_keys=True)
        Path(tmp).replace(path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _read(source: str, timeout_s: float) -> str:
    if source.startswith("https://"):
        try:
            with urllib.request.urlopen(source, timeout=timeout_s) as response:  # noqa: S310
                raw = response.read(MAX_REPORT_BYTES + 1)
        except (urllib.error.URLError, OSError) as exc:
            raise VantageError(f"cannot fetch control report: {exc}") from exc
    elif "://" in source:
        raise VantageError("control report URLs must use https://")
    else:
        try:
            with Path(source).open("rb") as handle:
                raw = handle.read(MAX_REPORT_BYTES + 1)
        except OSError as exc:
            raise VantageError(f"cannot read control report: {exc}") from exc
    if len(raw) > MAX_REPORT_BYTES:
        raise VantageError("control report is too large")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VantageError("control report is not UTF-8") from exc


def make_control_source(
    source: str, *, max_age_s: float = 300.0, timeout_s: float = 10.0, clock: Clock = time.time
) -> Callable[[], dict[str, bool]]:
    """Build a callable returning the fresh control results, or ``{}`` if unavailable.

    An empty mapping means "no control information": the burn engine then reports UNKNOWN
    and never declares a burn.
    """

    def fetch() -> dict[str, bool]:
        try:
            return parse_report(_read(source, timeout_s), now=clock(), max_age_s=max_age_s)
        except VantageError as exc:
            log.warning("no control information this cycle: %s", exc)
            return {}

    return fetch
