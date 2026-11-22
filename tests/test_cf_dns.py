"""Cloudflare DNS helper (no network)."""

from __future__ import annotations

from pathlib import Path

import pytest

from shahrah.cf_dns import load_env


def test_load_env_parses_token(tmp_path: Path) -> None:
    p = tmp_path / ".env"
    p.write_text('CF_API_TOKEN=secret\n# comment\nFOO=bar\n', encoding="utf-8")
    env = load_env(p)
    assert env["CF_API_TOKEN"] == "secret"
    assert env["FOO"] == "bar"


def test_load_env_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        load_env(tmp_path / "nope")