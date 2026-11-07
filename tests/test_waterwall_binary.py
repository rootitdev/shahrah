from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from shahrah.models import ConfigError
from shahrah.waterwall_binary import (
    WW_SHA256,
    cpu_has_avx2,
    infer_variant_from_binary,
    persist_cpu_variant,
    resolve_cpu_variant,
    variant_for_asset,
)

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = ROOT / "deploy" / "install.sh"


def test_old_cpu_x64_checksum_matches_release() -> None:
    assert (
        WW_SHA256[("x64", "old-cpu")]
        == "bdd20c083c15bc00df197b2f0562aeba013663230caefc95ca56292b839992b0"
    )


def test_cpu_has_avx2_from_text() -> None:
    assert not cpu_has_avx2("flags\t: fpu vme de pse\n")
    assert cpu_has_avx2("flags\t: fpu avx2 sse4_1\n")


def test_auto_picks_old_cpu_without_avx2() -> None:
    assert (
        resolve_cpu_variant(
            arch="x64", requested="auto", persist_path=None, cpuinfo_text="flags: sse\n"
        )
        == "old-cpu"
    )


def test_refuse_standard_on_non_avx2() -> None:
    with pytest.raises(ConfigError, match="refusing standard"):
        resolve_cpu_variant(
            arch="x64", requested="standard", persist_path=None, cpuinfo_text="flags: sse\n"
        )


def test_persisted_old_cpu_survives_auto_on_capable_cpu(tmp_path: Path) -> None:
    persist = tmp_path / "variant"
    persist_cpu_variant("old-cpu", persist)
    assert (
        resolve_cpu_variant(
            arch="x64",
            requested="auto",
            persist_path=persist,
            cpuinfo_text="flags: avx2\n",
        )
        == "old-cpu"
    )


def test_infer_variant_from_installed_binary(tmp_path: Path) -> None:
    blob = b"waterwall-test-binary"
    path = tmp_path / "waterwall"
    path.write_bytes(blob)
    assert infer_variant_from_binary(path) is None
    digest = hashlib.sha256(blob).hexdigest()
    # Wrong digest should not match
    assert digest not in WW_SHA256.values()


def test_cli_waterwall_binary_plan_json(tmp_path: Path) -> None:
    cpuinfo = tmp_path / "cpu"
    cpuinfo.write_text("flags: avx2\n", encoding="utf-8")
    out = subprocess.check_output(
        [
            sys.executable,
            "-m",
            "shahrah",
            "waterwall-binary",
            "plan",
            "--arch",
            "x64",
            "--variant",
            "auto",
            "--cpuinfo",
            str(cpuinfo),
        ],
        cwd=ROOT,
        env={**dict(__import__("os").environ), "PYTHONPATH": str(ROOT / "src")},
        text=True,
    )
    data = json.loads(out)
    assert data["variant"] == "standard"
    assert data["asset"] == "Waterwall-linux-gcc-x64.zip"
    assert data["sha256"] == WW_SHA256[("x64", "standard")]


def test_variant_for_asset_names() -> None:
    assert variant_for_asset("x64", "old-cpu") == (
        "Waterwall-linux-gcc-x64-old-cpu.zip",
        WW_SHA256[("x64", "old-cpu")],
    )


def test_detect_ssh_port_avoids_sigpipe_under_pipefail() -> None:
    """Regression: awk 'exit' in a pipeline used to yield rc 141 with pipefail during manifest."""
    script = rf"""
set -Eeuo pipefail
SSH_PORT=""
source {INSTALL_SH}
sshd() {{
  printf 'port 2222\nport 22\n'
}}
detect_ssh_port
test "$SSH_PORT" = 2222
"""
    subprocess.run(["bash", "-c", script], check=True, cwd=ROOT)
