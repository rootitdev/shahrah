from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from shahrah.cli import main
from shahrah.models import ConfigError
from shahrah.sni_scout import ScoutResult, ranking, scout


def test_rejects_ips_and_risky_apple_targets() -> None:
    with pytest.raises(ConfigError, match="domain name"):
        scout(["203.0.113.10"])
    with pytest.raises(ConfigError, match="risky"):
        scout(["www.apple.com"])


def test_ranking_keeps_only_successes_in_latency_order() -> None:
    results = [
        ScoutResult("slow.example", True, 80.0, "TLSv1.3", "h2"),
        ScoutResult("dead.example", False, None, None, None, "timeout"),
        ScoutResult("fast.example", True, 20.0, "TLSv1.3", "h2"),
    ]
    assert ranking(results) == ("fast.example", "slow.example")


def test_handshake_rejects_tls12(monkeypatch: pytest.MonkeyPatch) -> None:
    tls = MagicMock()
    tls.version.return_value = "TLSv1.2"
    tls.selected_alpn_protocol.return_value = "http/1.1"
    tls.getpeercert.return_value = {"subject": ()}
    tls.__enter__.return_value = tls
    tls.__exit__.return_value = False

    raw = MagicMock()
    raw.__enter__.return_value = raw
    raw.__exit__.return_value = False

    context = MagicMock()
    context.wrap_socket.return_value = tls
    monkeypatch.setattr("shahrah.sni_scout.ssl.create_default_context", lambda: context)
    monkeypatch.setattr("shahrah.sni_scout.socket.create_connection", lambda *a, **k: raw)

    result = scout(["www.example.com"])[0]
    assert not result.ok and "TLS 1.3" in result.detail


def test_cli_json_output(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "shahrah.sni_scout.scout",
        lambda hosts, **kw: [
            ScoutResult(hosts[0], True, 12.3, "TLSv1.3", "h2", "ok"),
            ScoutResult("bad.example", False, None, None, None, "timeout"),
        ],
    )
    assert main(["sni-scout", "www.example.com", "bad.example", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["ok"] is True and payload[0]["host"] == "www.example.com"


@pytest.mark.e2e
def test_real_cloudflare_is_a_viable_reality_target() -> None:
    """Needs internet; skips cleanly when offline."""
    results = scout(["www.cloudflare.com"], timeout_s=8.0)
    if not results[0].ok:
        pytest.skip(results[0].detail)
    assert results[0].tls_version in {"TLSv1.3", "TLS 1.3"}
