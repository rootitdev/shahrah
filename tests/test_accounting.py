from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from shahrah import accounting
from shahrah.cli import main
from shahrah.models import ConfigError, Profile
from shahrah.state import NodeState, save_state


def test_parse_stat_name_and_payload() -> None:
    assert accounting.parse_stat_name("user>>>alice>>>traffic>>>uplink") == ("alice", "uplink")
    assert accounting.parse_stat_name("inbound>>>api>>>traffic>>>uplink") is None
    traffic = accounting.parse_stats_payload(
        {
            "stat": [
                {"name": "user>>>alice>>>traffic>>>uplink", "value": "100"},
                {"name": "user>>>alice>>>traffic>>>downlink", "value": 50},
                {"name": "user>>>bob>>>traffic>>>uplink", "value": "7"},
                {"name": "inbound>>>main>>>traffic>>>uplink", "value": "999"},
            ]
        }
    )
    assert traffic["alice"].as_dict() == {
        "label": "alice",
        "uplink": 100,
        "downlink": 50,
        "total": 150,
    }
    assert traffic["bob"].uplink == 7 and traffic["bob"].downlink == 0


def test_delta_since_handles_reset() -> None:
    prev = {"alice": accounting.UserTraffic("alice", 100, 20)}
    current = {"alice": accounting.UserTraffic("alice", 150, 30)}
    assert accounting.delta_since(current, prev)["alice"].total == 60
    after_reset = {"alice": accounting.UserTraffic("alice", 5, 1)}
    assert accounting.delta_since(after_reset, prev)["alice"].total == 6


def test_query_stats_rejects_non_loopback() -> None:
    with pytest.raises(ConfigError, match="loopback"):
        accounting.query_stats(server="203.0.113.9:10085")


def test_query_stats_parses_xray_cli_json() -> None:
    payload = {
        "stat": [
            {"name": "user>>>alice>>>traffic>>>uplink", "value": "11"},
            {"name": "user>>>alice>>>traffic>>>downlink", "value": "22"},
        ]
    }

    class Result:
        returncode = 0
        stdout = json.dumps(payload)
        stderr = ""

    with patch("shahrah.accounting.subprocess.run", return_value=Result()) as run:
        traffic = accounting.query_stats(xray_bin="/usr/local/bin/xray", server="127.0.0.1:10085")
    assert traffic["alice"].total == 33
    assert run.call_args.args[0][:3] == ["/usr/local/bin/xray", "api", "statsquery"]


def test_cli_stats_api_and_usage(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    state_path = tmp_path / "state.json"
    state = NodeState.create(
        public_host="vpn.example.org",
        target_host="www.example.com",
        profile=Profile.REALITY_VISION,
    )
    save_state(state_path, state)
    assert main(["--state", str(state_path), "stats-api"]) == 0
    loaded = NodeState.from_json(state_path.read_text(encoding="utf-8"))
    assert loaded.stats_api_port == 10085
    assert "stats_api_port -> 10085" in capsys.readouterr().out

    fake = {"alice": accounting.UserTraffic("alice", 1, 2)}
    with patch("shahrah.accounting.query_stats", return_value=fake):
        assert main(["--state", str(state_path), "usage", "--json"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["alice"]["total"] == 3

    assert main(["--state", str(state_path), "stats-api", "--off"]) == 0
    assert NodeState.from_json(state_path.read_text(encoding="utf-8")).stats_api_port is None
