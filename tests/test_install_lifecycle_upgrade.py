"""Regression: git-updated source must run before stale /usr/local/bin/shahrah."""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "deploy" / "install.sh"
LIB = ROOT / "deploy" / "lib" / "shahrah-cli.sh"


def _bash(script: str, *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        ["bash", "-c", script],
        cwd=ROOT,
        env=merged,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_install_orders_bootstrap_before_xray() -> None:
    text = INSTALL.read_text(encoding="utf-8")
    main = text[text.index("main() {") :]
    assert main.index("install_app") < main.index("install_xray")
    assert 'relay|brain) log "skipping Xray download' in text


def test_stale_system_cli_bootstrap_from_source(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    stale = fake_bin / "shahrah"
    stale.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env bash
            echo "shahrah: error: invalid choice: '$2'" >&2
            exit 2
            """
        ),
        encoding="utf-8",
    )
    stale.chmod(0o755)
    app = tmp_path / "opt"
    script = f"""
set -euo pipefail
export SHAHRAH_SRC_DIR='{ROOT.as_posix()}'
export SHAHRAH_APP_DIR='{app.as_posix()}'
export PATH='{fake_bin.as_posix()}:/usr/bin:/bin'
source '{LIB.as_posix()}'
bootstrap_shahrah_cli
shahrah_cli lifecycle has-feature --name uninstall-plan
shahrah_cli uninstall-plan --json | head -c 20
"""
    result = _bash(script)
    if result.returncode != 0:
        pytest.fail(result.stderr + result.stdout)


def test_fake_old_cli_rejects_uninstall_plan(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    stale = fake_bin / "shahrah"
    stale.write_text(
        "#!/bin/sh\necho invalid choice uninstall-plan >&2\nexit 2\n",
        encoding="utf-8",
    )
    stale.chmod(0o755)
    env = {"PATH": f"{fake_bin}:{os.environ.get('PATH', '')}"}
    r = subprocess.run(["shahrah", "uninstall-plan"], capture_output=True, text=True, env=env)
    assert r.returncode != 0
    assert "invalid" in (r.stderr + r.stdout).lower()


def test_lifecycle_has_feature_new_cli() -> None:
    r = subprocess.run(
        ["python3", "-m", "shahrah", "lifecycle", "has-feature", "--name", "record-provenance"],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0
