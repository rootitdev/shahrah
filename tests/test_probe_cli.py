from __future__ import annotations

import pytest

from shahrah.cli import _probe_destinations
from shahrah.models import ConfigError


def test_default_destinations_cover_social_and_ai() -> None:
    dests = _probe_destinations([])
    hosts = {d.host for d in dests}
    assert "www.gstatic.com" in hosts
    assert "www.instagram.com" in hosts
    assert "telegram.org" in hosts
    assert "chatgpt.com" in hosts
    assert "claude.ai" in hosts


def test_dest_parser() -> None:
    dests = _probe_destinations(["example.com/generate_204", "cdn.example.com"])
    assert dests[0].path == "/generate_204"
    assert 204 in dests[0].expect_status
    assert dests[1].path == "/"


def test_bad_dest_rejected() -> None:
    with pytest.raises(ConfigError):
        _probe_destinations(["/nohost"])
