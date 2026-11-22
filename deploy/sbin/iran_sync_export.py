#!/usr/bin/env python3
"""Shahrah: apply instagram-multiplier CAT rules on exit pg-node Xray.

Legacy path kept for `instagram-multiplier` CLI. On NL/exit: patches the live
Xray JSON inside Docker `node`, then restarts xray.real so routing applies.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

for _libdir in (Path("/usr/local/lib/instagram-multiplier"),):
    if (_libdir / "instagram_multiplier.py").is_file():
        sys.path.insert(0, str(_libdir))
        break
else:
    raise SystemExit("instagram_multiplier module not found")

from instagram_multiplier import inject_into_core, load_settings  # noqa: E402

NODE = os.environ.get("IG_NODE_CONTAINER", "node")


def _run(cmd: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def running_config_path() -> str:
    out = _run(
        [
            "docker",
            "exec",
            NODE,
            "sh",
            "-c",
            "ps aux | grep 'xray.real -c' | grep -v grep | head -1",
        ]
    )
    m = re.search(r"-c\s+(\S+)", out.stdout)
    if not m:
        raise SystemExit("xray.real is not running inside docker " + NODE)
    return m.group(1)


def main() -> None:
    cfg_path = running_config_path()
    raw = _run(["docker", "exec", NODE, "cat", cfg_path]).stdout
    cfg = json.loads(raw)
    st = load_settings()
    n_rules = inject_into_core(cfg, st)
    new_json = json.dumps(cfg, ensure_ascii=False, indent=2) + "\n"
    proc = subprocess.run(
        ["docker", "exec", "-i", NODE, "tee", cfg_path],
        input=new_json,
        text=True,
        capture_output=True,
        timeout=90,
    )
    if proc.returncode != 0:
        raise SystemExit((proc.stderr or proc.stdout or "tee failed").strip())
    pid_out = subprocess.run(
        [
            "docker",
            "exec",
            NODE,
            "sh",
            "-c",
            "pgrep -f 'xray.real -c' | head -1",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    pid = (pid_out.stdout or "").strip()
    if pid.isdigit():
        subprocess.run(["docker", "exec", NODE, "kill", pid], timeout=15, check=False)
    print(f"ok rules={n_rules} users={len(st.user_ids)} file={Path(cfg_path).name}")


if __name__ == "__main__":
    main()