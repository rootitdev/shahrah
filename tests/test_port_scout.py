"""port_scout bank: score, assign, pick, seed, refresh with a stub probe."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shahrah import port_scout as ps
from shahrah.models import ConfigError


def test_seed_and_score_prefers_high_ports(tmp_path: Path) -> None:
    bank = ps.seed(ps.PortBank(target_host="203.0.113.10"))
    assert any(c.port == 10443 and c.proto == "tcp" for c in bank.candidates)
    now = 1_700_000_000.0
    # mark a well-known and a high port as reachable
    for port, lat in ((443, 40.0), (10443, 35.0)):
        bank = bank.upsert(
            ps.Candidate(
                port=port,
                proto="tcp",
                verified_at=now,
                ok=True,
                latency_ms=lat,
                observations=(
                    ps.Observation(vantage="iran", asn=49556, at=now, ok=True, latency_ms=lat),
                ),
            )
        )
    ranked = bank.ranked(now, proto="tcp")
    usable = [s for s in ranked if s.usable]
    assert usable
    assert usable[0].port == 10443  # high port first
    assert usable[0].total > next(s for s in usable if s.port == 443).total


def test_refresh_stub_probe_and_pick(tmp_path: Path) -> None:
    bank = ps.PortBank(target_host="203.0.113.10").add([28080, 22], "tcp", 0.0)
    now = 1_700_000_100.0

    def probe(host: str, port: int, proto: str, timeout_s: float) -> ps.ProbeResult:
        assert host == "203.0.113.10"
        ok = port == 28080
        return ps.ProbeResult(port, proto, ok, 25.0 if ok else None, "stub")

    bank = ps.refresh(bank, now, only_due=False, probe=probe, vantage="iran", asn=49556)
    assert bank.get(28080, "tcp").ok
    assert not bank.get(22, "tcp").ok
    picked = ps.pick(bank, now, proto="tcp")
    assert picked is not None and picked.port == 28080
    bank = ps.assign(bank, 28080, "tcp", "alice")
    # with only assigned usable ports, pick falls back to the assigned one
    assert ps.pick(bank, now, proto="tcp", prefer_unassigned=True).port == 28080
    assert ps.pick(bank, now, proto="tcp", prefer_unassigned=False).port == 28080


def test_load_save_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "port-bank.json"
    bank = ps.seed(ps.PortBank(target_host="exit.example"))
    ps.save_bank(path, bank)
    loaded = ps.load_bank(path)
    assert loaded.target_host == "exit.example"
    assert len(loaded.candidates) == len(bank.candidates)
    data = json.loads(path.read_text())
    assert data["version"] == ps.BANK_VERSION


def test_bad_proto() -> None:
    with pytest.raises(ConfigError):
        ps.PortBank().add([9], "sctp", 0.0)
