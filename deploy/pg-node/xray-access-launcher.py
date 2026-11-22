#!/usr/bin/python3
"""PasarGuard Node → Xray launcher that restores access logging.

pg-node feeds Xray with ``-c stdin:`` and strips ``log.access``. sni-watch and
ops visibility need that file. This process:

1. reads the JSON config from stdin (when ``stdin:`` is used);
2. forces ``log.access`` / ``log.error`` to known paths;
3. ``os.execv`` into the real Xray binary so pg-node's supervisor still owns the
   Xray PID (no double-listen / leaked children).

Install (exit host)::

  deploy/pg-node/install-xray-access-launcher.sh

Prefer the static Go launcher (Docker node image has no Python)::

  sudo FORCE_REBUILD=1 bash deploy/pg-node/install-xray-access-launcher.sh

Live access path: ``/var/lib/pg-node/logs/access.log``.
"""

from __future__ import annotations

import fcntl
import json
import os
import sys
from pathlib import Path

REAL = os.environ.get("XRAY_REAL", "/var/lib/pg-node/xray-core/xray.real")
ACCESS = os.environ.get("XRAY_ACCESS_LOG", "/var/lib/pg-node/logs/access.log")
ERROR = os.environ.get("XRAY_ERROR_LOG", "/var/lib/pg-node/logs/error.log")
F_SETPIPE_SZ = getattr(fcntl, "F_SETPIPE_SZ", 1031)


def _ensure_log_files() -> None:
    for path in (ACCESS, ERROR):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.touch()
        try:
            os.chmod(p, 0o644)
        except OSError:
            pass


def inject(raw: bytes) -> bytes:
    try:
        cfg = json.loads(raw)
    except Exception:
        return raw
    if not isinstance(cfg, dict):
        return raw
    log = cfg.setdefault("log", {})
    if not isinstance(log, dict):
        return raw
    log["access"] = ACCESS
    if not log.get("error"):
        log["error"] = ERROR
    if not log.get("loglevel"):
        log["loglevel"] = "warning"
    return json.dumps(cfg, ensure_ascii=False).encode()


def exec_real(args: list[str], data: bytes | None) -> None:
    if not Path(REAL).is_file():
        sys.stderr.write(f"xray-access-launcher: missing REAL binary: {REAL}\n")
        raise SystemExit(127)
    argv = [REAL, *args]
    if data is None:
        os.execv(REAL, argv)
    r, w = os.pipe()
    try:
        fcntl.fcntl(w, F_SETPIPE_SZ, max(1 << 20, len(data) + 4096))
    except OSError:
        pass
    os.write(w, data)
    os.close(w)
    os.dup2(r, 0)
    os.close(r)
    os.execv(REAL, argv)


def main() -> int:
    _ensure_log_files()
    args = sys.argv[1:]
    uses_stdin = (not args) or any(a == "stdin:" or a.endswith("stdin:") for a in args)
    if not uses_stdin:
        exec_real(args, None)
        return 1
    data = inject(sys.stdin.buffer.read())
    exec_real(args, data)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
