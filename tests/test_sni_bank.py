from __future__ import annotations

import json
from dataclasses import replace as _replace
from pathlib import Path

import pytest

from shahrah import sni_bank as sb
from shahrah.cli import main
from shahrah.models import ConfigError
from shahrah.sni_scout import ScoutResult

NOW = 1_800_000_000.0
DAY = 86400.0
NODE = "203.0.113.10"


def _ok(host: str, ms: float = 30.0, alpn: str = "h2") -> ScoutResult:
    return ScoutResult(host, True, ms, "TLSv1.3", alpn, "ok", cert_not_after=NOW + 60 * DAY)


def _bank(*hosts: str, region: str = "foreign") -> sb.SniBank:
    return sb.SniBank(node_ip=NODE).add(hosts, region, NOW - DAY)


def _resolver(table: dict[str, list[str]]):
    return lambda name: table.get(name, [])


def test_score_prefers_dns_plausible_names_over_faster_mismatches() -> None:
    bank = _bank("own.example", "fast-famous.example")
    resolve = _resolver({"own.example": [NODE], "fast-famous.example": ["198.51.100.1"]})
    shakes = {
        "own.example": _ok("own.example", 120.0),
        "fast-famous.example": _ok("fast-famous.example", 10.0),
    }
    bank = sb.refresh(bank, NOW, handshake=lambda h, p, t: shakes[h], resolver=resolve)
    ranked = bank.ranked(NOW)
    assert next(s.host for s in ranked) == "own.example"
    famous = next(s for s in ranked if s.host == "fast-famous.example")
    assert famous.factors["dns"] == pytest.approx(sb.DNS_FACTOR["mismatch"])
    assert any("mismatch" in r for r in famous.reasons)
    strict = {s.host: s for s in bank.ranked(NOW, strict_dns=True)}
    assert strict["fast-famous.example"].total < strict["own.example"].total


def test_tls_failure_gates_score_and_cert_expiry_is_penalised() -> None:
    dead = sb.Candidate("dead.example", verified_at=NOW, tls_ok=False, detail="timeout")
    assert sb.score(dead, NOW).total == 0.0
    good = sb.Candidate(
        "x.example",
        verified_at=NOW,
        tls_ok=True,
        alpn="h2",
        latency_ms=40,
        cert_not_after=NOW + 60 * DAY,
        dns_verdict="own-domain",
    )
    dying = sb.Candidate(
        "y.example",
        verified_at=NOW,
        tls_ok=True,
        alpn="h2",
        latency_ms=40,
        cert_not_after=NOW + DAY,
        dns_verdict="own-domain",
    )
    assert sb.score(good, NOW).total > sb.score(dying, NOW).total
    assert "certificate expires within 3 days" in sb.score(dying, NOW).reasons


def test_candidates_expire_after_ttl_and_rotation_moves_off_them() -> None:
    fresh = sb.Candidate(
        "b.example",
        verified_at=NOW - 3600,
        tls_ok=True,
        alpn="h2",
        latency_ms=50,
        dns_verdict="own-domain",
    )
    stale = sb.Candidate(
        "a.example",
        verified_at=NOW - 13 * 3600,
        tls_ok=True,
        alpn="h2",
        latency_ms=20,
        dns_verdict="own-domain",
    )
    bank = sb.activate(sb.SniBank(candidates=(fresh, stale)), "foreign", "a.example")
    assert stale.expired(NOW) and not fresh.expired(NOW)
    rot = sb.rotation(bank, "foreign", NOW)
    assert rot.rotate and rot.pick == "b.example" and "expired" in rot.reason
    # nothing usable -> no rotation, explicit advice
    empty = sb.rotation(sb.SniBank(candidates=(stale,)), "foreign", NOW)
    assert not empty.rotate and empty.pick is None


def test_rotation_has_hysteresis() -> None:
    a = sb.Candidate(
        "a.example",
        verified_at=NOW,
        tls_ok=True,
        alpn="h2",
        latency_ms=60,
        dns_verdict="own-domain",
    )
    b = sb.Candidate(
        "b.example",
        verified_at=NOW,
        tls_ok=True,
        alpn="h2",
        latency_ms=40,
        dns_verdict="own-domain",
    )
    bank = sb.activate(sb.SniBank(candidates=(a, b)), "foreign", "a.example")
    assert not sb.rotation(bank, "foreign", NOW).rotate  # slightly better is not enough


def test_multi_asn_reports_block_on_one_carrier_demotes_the_name() -> None:
    """Simulated vantages on two Iranian ASNs + a foreign control."""
    bank = _bank("cdn-ish.example", "plain.example")
    resolve = _resolver({"cdn-ish.example": ["203.0.113.77"], "plain.example": ["203.0.113.78"]})
    bank = sb.refresh(bank, NOW, handshake=lambda h, p, t: _ok(h), resolver=resolve)
    reports = [
        {
            "version": 1,
            "vantage": "ir-mci",
            "asn": 197207,
            "generated_at": NOW - 60,
            "sni": {
                "cdn-ish.example": {"ok": True},
                "plain.example": {"ok": False, "blocked": True},
            },
        },
        {
            "version": 1,
            "vantage": "ir-irancell",
            "asn": 44244,
            "generated_at": NOW - 60,
            "sni": {"cdn-ish.example": {"ok": True}, "plain.example": {"ok": True}},
        },
        {
            "version": 1,
            "vantage": "control",
            "asn": None,
            "generated_at": NOW - 60,
            "sni": {
                "cdn-ish.example": {"ok": True},
                "plain.example": {"ok": True},
                "unknown.example": {"ok": True},
            },
        },
        # stale report is ignored
        {
            "version": 1,
            "vantage": "ir-rightel",
            "asn": 57218,
            "generated_at": NOW - 2 * DAY,
            "sni": {"cdn-ish.example": {"ok": False, "blocked": True}},
        },
    ]
    for rep in reports:
        bank = sb.merge_vantage_report(bank, rep, now=NOW)
    assert bank.get("unknown.example") is None
    scores = {s.host: s for s in bank.ranked(NOW)}
    assert scores["plain.example"].total <= 10.0
    assert any("blocked on ir-mci/AS197207" in r for r in scores["plain.example"].reasons)
    assert scores["cdn-ish.example"].factors["vantage"] == 1.0
    assert sb.passing_snis(bank, 197207, NOW) == ("cdn-ish.example",)
    assert sb.passing_snis(bank, 44244, NOW) == ("cdn-ish.example", "plain.example")
    with pytest.raises(ConfigError):
        sb.merge_vantage_report(bank, {"version": 2}, now=NOW)


def test_vantage_report_marks_resets_as_blocks_not_cert_errors() -> None:
    rep = sb.build_vantage_report(
        [
            ScoutResult("r.example", False, None, None, None, "ConnectionResetError: reset"),
            ScoutResult("c.example", False, None, None, None, "cert: bad"),
            _ok("g.example"),
        ],
        vantage="ir-mci",
        asn=197207,
        now=NOW,
    )
    assert rep["sni"]["r.example"]["blocked"] and not rep["sni"]["c.example"]["blocked"]
    assert rep["sni"]["g.example"]["ok"]


def test_bank_roundtrip_has_no_secrets_and_rejects_ips(tmp_path: Path) -> None:
    bank = sb.activate(_bank("own.example"), "foreign", "own.example")
    path = tmp_path / "bank.json"
    sb.save_bank(path, bank)
    assert sb.load_bank(path) == bank
    text = path.read_text()
    assert "key" not in text.lower().replace('"active"', "")
    with pytest.raises(ConfigError):
        sb.Candidate("192.0.2.1")
    with pytest.raises(ConfigError):
        sb.Candidate("x.example", region="mars")


def test_cli_seed_list_score_rotate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    bank = tmp_path / "bank.json"
    monkeypatch.setattr("shahrah.sni_scout._handshake", lambda h, p, t: _ok(h))
    monkeypatch.setattr(
        "shahrah.sni_dns.system_resolver",
        lambda name: [NODE] if name == "own.example" else ["198.51.100.9"],
    )
    assert (
        main(
            [
                "sni-bank",
                "--bank",
                str(bank),
                "add",
                "own.example",
                "other.example",
                "--node-ip",
                NODE,
            ]
        )
        == 0
    )
    assert main(["sni-bank", "--bank", str(bank), "refresh", "--all"]) == 0
    assert main(["sni-bank", "--bank", str(bank), "rotate", "--apply"]) == 0
    capsys.readouterr()
    assert main(["sni-bank", "--bank", str(bank), "list", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["host"] == "own.example" and rows[0]["usable"]
    assert json.loads(bank.read_text())["active"] == {"foreign": "own.example"}
    assert main(["sni-bank", "--bank", str(bank), "seed"]) == 0
    assert len(json.loads(bank.read_text())["candidates"]) > 5


def _link(sni: str) -> str:
    return (
        "vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443"
        f"?security=reality&sni={sni}&pbk=abc&sid=ab&type=tcp&flow=xtls-rprx-vision#n"
    )


def test_readycheck_flags_unknown_expired_and_blocked_snis() -> None:
    from shahrah.readycheck import check_sni_bank

    good = sb.Candidate(
        "good.example",
        verified_at=NOW,
        tls_ok=True,
        alpn="h2",
        latency_ms=30,
        dns_verdict="own-domain",
    )
    old = _replace(good, host="old.example", verified_at=NOW - 2 * DAY)
    blocked = _replace(
        good,
        host="bad.example",
        observations=(sb.Observation("ir-mci", 197207, NOW - 60, ok=False, blocked=True),),
    )
    bank = sb.SniBank(candidates=(good, old, blocked))
    body = "\n".join(
        _link(s) for s in ("good.example", "old.example", "bad.example", "new.example")
    )
    problems = dict(check_sni_bank(body, bank, NOW))
    assert "good.example" not in problems
    assert "expired" in problems["old.example"]
    assert "blocked on ir-mci" in problems["bad.example"]
    assert "not in the SNI bank" in problems["new.example"]


def test_tactics_profile_takes_snis_that_pass_on_its_asn() -> None:
    from shahrah.oracle import Mode
    from shahrah.tactics import TacticsProfile, with_bank_snis

    base = sb.Candidate(
        "a.example",
        verified_at=NOW,
        tls_ok=True,
        alpn="h2",
        latency_ms=30,
        dns_verdict="own-domain",
    )
    a = _replace(base, observations=(sb.Observation("ir-mci", 197207, NOW - 60, ok=True),))
    pinned_bad = _replace(
        base,
        host="pinned.example",
        observations=(sb.Observation("ir-mci", 197207, NOW - 60, ok=False, blocked=True),),
    )
    bank = sb.SniBank(candidates=(a, pinned_bad))
    prof = TacticsProfile(
        "mci", Mode.RESTRICTED, asns=(197207,), sni_allowlist=("pinned.example", "keep.example")
    )
    assert with_bank_snis(prof, bank, NOW).sni_allowlist == ("a.example", "keep.example")
    generic = TacticsProfile("any", Mode.NORMAL)
    assert with_bank_snis(generic, bank, NOW) is generic
