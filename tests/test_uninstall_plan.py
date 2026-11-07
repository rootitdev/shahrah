from __future__ import annotations

import json

import pytest

from shahrah.models import ConfigError
from shahrah.ownership import (
    BinaryProvenanceEntry,
    InstallManifest,
    build_uninstall_plan,
)


def test_manifest_rejects_unknown_unit() -> None:
    raw = json.dumps({"version": 2, "units": ["ssh.service"]})
    with pytest.raises(ConfigError):
        InstallManifest.from_json(raw)


def test_build_plan_includes_unit_files_not_binaries_without_provenance() -> None:
    manifest = InstallManifest(public_ports=[443])
    plan = build_uninstall_plan(manifest, purge_data=True, provenance=[])
    assert "/etc/systemd/system/shahrah-xray.service" in plan["unit_files"]
    assert "/usr/local/bin/xray" not in plan["paths"]
    assert plan["binaries"] == []


def test_provenance_required_to_remove_binary(tmp_path) -> None:
    manifest = InstallManifest()
    entry = BinaryProvenanceEntry(
        path="/usr/local/bin/xray",
        kind="xray",
        sha256="0" * 64,
        installed_utc="2020-01-01T00:00:00Z",
    )
    plan = build_uninstall_plan(manifest, purge_data=True, provenance=[entry])
    assert "/usr/local/bin/xray" not in plan["binaries"]
