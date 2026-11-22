"""Resolve PasarGuard docker container name or host DB path (DE master)."""

from __future__ import annotations

import subprocess
from pathlib import Path

HOST_DB = Path("/var/lib/pasarguard/db.sqlite3")


def pasarguard_container() -> str:
  for name in ("pasarguard", "pasarguard-pasarguard-1"):
    r = subprocess.run(
      ["docker", "inspect", "-f", "{{.State.Running}}", name],
      capture_output=True,
      text=True,
      timeout=10,
    )
    if r.returncode == 0 and (r.stdout or "").strip() == "true":
      return name
  r = subprocess.run(
    ["docker", "ps", "--format", "{{.Names}}"],
    capture_output=True,
    text=True,
    timeout=10,
  )
  if r.returncode == 0:
    for line in (r.stdout or "").splitlines():
      if "pasarguard" in line.lower():
        return line.strip()
  raise RuntimeError("no running PasarGuard container")


def pasarguard_db_via_python(py_body: str, stdin: str = "") -> str:
  """Run Python that reads PasarGuard sqlite; prefer host DB file when present."""
  if HOST_DB.is_file():
    wrapped = (
      "import os\n"
      f"os.environ.setdefault('PG_DB', '{HOST_DB.as_posix()}')\n"
      + py_body.replace(
        '"/var/lib/pasarguard/db.sqlite3"',
        "os.environ.get('PG_DB', '/var/lib/pasarguard/db.sqlite3')",
      )
    )
    r = subprocess.run(
      ["python3", "-c", wrapped],
      input=stdin,
      capture_output=True,
      text=True,
      timeout=30,
    )
    if r.returncode != 0:
      raise RuntimeError((r.stderr or r.stdout or "python failed").strip())
    return r.stdout or ""

  container = pasarguard_container()
  r = subprocess.run(
    ["docker", "exec", "-i", container, "/code/.venv/bin/python", "-c", py_body],
    input=stdin,
    capture_output=True,
    text=True,
    timeout=30,
  )
  if r.returncode != 0:
    raise RuntimeError((r.stderr or r.stdout or "docker exec failed").strip())
  return r.stdout or ""