from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from shahrah.models import ConfigError
from shahrah.waterwall_binary import (
    WW_ELF_SHA256,
    WW_ZIP_SHA256,
    cpu_has_avx2,
    persist_cpu_variant,
    resolve_cpu_variant,
    should_skip_waterwall_download,
    variant_for_asset,
    verify_installed_binary,
)

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = ROOT / "deploy" / "install.sh"
LIB = ROOT / "deploy" / "lib" / "shahrah-cli.sh"


def test_old_cpu_x64_zip_checksum_matches_release() -> None:
    assert (
        WW_ZIP_SHA256[("x64", "old-cpu")]
        == "bdd20c083c15bc00df197b2f0562aeba013663230caefc95ca56292b839992b0"
    )


def test_elf_and_zip_digests_differ() -> None:
    assert WW_ELF_SHA256[("x64", "old-cpu")] != WW_ZIP_SHA256[("x64", "old-cpu")]


def test_cpu_has_avx2_from_text() -> None:
    assert not cpu_has_avx2("flags\t: fpu vme de pse\n")
    assert cpu_has_avx2("flags\t: fpu avx2 sse4_1\n")


def test_auto_picks_old_cpu_without_avx2(tmp_path: Path) -> None:
    assert (
        resolve_cpu_variant(
            arch="x64",
            requested="auto",
            persist_path=tmp_path / "missing",
            cpuinfo_text="flags: sse\n",
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


def test_unknown_arch_fail_closed() -> None:
    with pytest.raises(ConfigError, match="unsupported"):
        variant_for_asset("mips", "standard")
    with pytest.raises(ConfigError, match="unsupported"):
        resolve_cpu_variant(arch="riscv64", requested="auto")


def test_skip_download_requires_elf_match_not_zip(tmp_path: Path) -> None:
    persist = tmp_path / "variant"
    persist_cpu_variant("old-cpu", persist)
    blob = tmp_path / "ww"
    blob.write_bytes(b"not-the-real-elf")
    blob.chmod(0o755)
    assert not should_skip_waterwall_download(
        arch="x64",
        variant="old-cpu",
        persist_path=persist,
        installed=blob,
    )


def test_skip_download_true_when_elf_matches(tmp_path: Path) -> None:
    persist = tmp_path / "variant"
    persist_cpu_variant("old-cpu", persist)
    elf = tmp_path / "ww"
    # Content arbitrary; verify_installed_binary is mocked to assert path is consulted.
    elf.write_bytes(b"x")
    elf.chmod(0o755)
    with patch(
        "shahrah.waterwall_binary.verify_installed_binary",
        return_value=True,
    ) as verify:
        assert should_skip_waterwall_download(
            arch="x64",
            variant="old-cpu",
            persist_path=persist,
            installed=elf,
        )
        verify.assert_called_once()


def test_cli_waterwall_binary_plan_json(tmp_path: Path) -> None:
    cpuinfo = tmp_path / "cpu"
    cpuinfo.write_text("flags: avx2\n", encoding="utf-8")
    persist = tmp_path / "persist"
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
            "--persist",
            str(persist),
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        text=True,
    )
    data = json.loads(out)
    assert data["variant"] == "standard"
    assert data["zip_sha256"] == WW_ZIP_SHA256[("x64", "standard")]
    assert data["elf_sha256"] == WW_ELF_SHA256[("x64", "standard")]


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


def test_stale_venv_without_waterwall_binary_bootstraps(tmp_path: Path) -> None:
    """71b2339-era venv answers lifecycle but lacks waterwall-binary plan."""
    venv_bin = tmp_path / "venv/bin"
    venv_bin.mkdir(parents=True)
    stale = venv_bin / "shahrah"
    stale.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env bash
            if [[ "$1" == lifecycle && "$2" == has-feature ]]; then exit 0; fi
            if [[ "$1" == waterwall-binary && "$2" == plan && "$3" == --help ]]; then
              echo "invalid choice: waterwall-binary" >&2
              exit 2
            fi
            echo "unexpected: $*" >&2
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
export PATH='{venv_bin.as_posix()}:/usr/bin:/bin'
source '{LIB.as_posix()}'
resolve_shahrah_cli_for_install waterwall-binary
printf '' > '{tmp_path.as_posix()}/cpu'
shahrah_cli waterwall-binary plan --arch x64 --variant auto \\
  --cpuinfo '{tmp_path.as_posix()}/cpu' --persist '{tmp_path.as_posix()}/p' | head -c 40
"""
    result = _bash(script)
    assert result.returncode == 0, result.stderr + result.stdout
    assert (app / "venv/bin/shahrah").exists()


def test_detect_ssh_port_mapfile_succeeds_with_long_sshd_output() -> None:
    """mapfile reads full sshd -T stream (no early-close SIGPIPE under pipefail)."""
    script = f"""
set -Eeuo pipefail
SSH_PORT=""
source {INSTALL_SH}
sshd() {{ for i in $(seq 1 500); do echo port $((2200+i)); done; echo port 22; }}
detect_ssh_port
test "$SSH_PORT" = 2201
"""
    result = _bash(script)
    assert result.returncode == 0, result.stderr + result.stdout


def test_detect_ssh_port_mapfile_succeeds() -> None:
    script = f"""
set -Eeuo pipefail
SSH_PORT=""
source {INSTALL_SH}
sshd() {{ printf 'port 2222\\nport 22\\n'; }}
detect_ssh_port
test "$SSH_PORT" = 2222
"""
    result = _bash(script)
    assert result.returncode == 0, result.stderr + result.stdout


def test_ensure_waterwall_host_tools_installs_unzip(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    script = f"""
set -euo pipefail
    export PATH='{fake_bin.as_posix()}:/usr/bin:/bin'
source {INSTALL_SH}
    command() {{
      if [[ "$1" == -v && "$2" == unzip ]]; then
        [[ -x '{fake_bin.as_posix()}/unzip' ]] || return 1
        builtin command -v "$2"
        return 0
      fi
      if [[ "$1" == -v && "$2" == curl ]]; then
        [[ -x '{fake_bin.as_posix()}/curl' ]] || return 1
        builtin command -v "$2"
        return 0
      fi
      builtin command "$@"
    }}
    export -f command
    apt-get() {{
      if [[ "$1" == install ]]; then
        touch '{fake_bin.as_posix()}/unzip'
        chmod 755 '{fake_bin.as_posix()}/unzip'
        touch '{fake_bin.as_posix()}/curl'
        chmod 755 '{fake_bin.as_posix()}/curl'
      fi
      return 0
    }}
    export -f apt-get
    command -v unzip >/dev/null && exit 1
ensure_waterwall_host_tools
command -v unzip >/dev/null
command -v curl >/dev/null
"""
    result = _bash(script)
    assert result.returncode == 0, result.stderr + result.stdout


def test_verify_installed_binary_uses_elf_table(tmp_path: Path) -> None:
    path = tmp_path / "b"
    path.write_bytes(b"fake")
    path.chmod(0o755)
    assert not verify_installed_binary(path, arch="x64", variant="old-cpu")
