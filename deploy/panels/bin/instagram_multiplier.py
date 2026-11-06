#!/usr/bin/env python3
"""Selective Instagram traffic multiplier for Xray cores.

Reusable: copy this file, a users list, and an env file. Call inject_into_core()
on the Xray JSON before it is applied, and weighted_user_deltas() when ingesting
StatsService counters.

Xray does not expose user×destination stats. Per-user Instagram bytes come from
a dedicated outbound tag CAT-instagram-u<id> plus a routing rule that matches
only that user's email (panel user id) and Instagram domains.

Non-selected users are not given rules or outbounds.
"""
from __future__ import annotations

import copy
import gzip
import json
import os
import re
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

TAG_PREFIX = "CAT-instagram-u"
DEFAULT_MULTIPLIER = 1.5
DEFAULT_DOMAINS = (
    "geosite:instagram",
    "full:instagram.com",
    "domain:cdninstagram.com",
    "domain:ig.me",
    # pornhub / xnxx / xvideos (+ main CDNs) — same multiplier as Instagram
    "domain:pornhub.com",
    "domain:phncdn.com",
    "domain:pornhub.org",
    "domain:pornhub.net",
    "domain:xnxx.com",
    "domain:xnxx.tv",
    "domain:xnxx.es",
    "domain:xvideos.com",
    "domain:xvideos-cdn.com",
)


@dataclass
class Settings:
    user_ids: list[int] = field(default_factory=list)
    multiplier: float = DEFAULT_MULTIPLIER
    domains: list[str] = field(default_factory=lambda: list(DEFAULT_DOMAINS))


def tag_for(uid: int) -> str:
    return f"{TAG_PREFIX}{int(uid)}"


def is_cat_tag(tag: str | None) -> bool:
    t = tag or ""
    return t.startswith(TAG_PREFIX) and t[len(TAG_PREFIX) :].isdigit()


def parse_user_ids(text: str) -> list[int]:
    ids: list[int] = []
    seen: set[int] = set()
    for ln in text.splitlines():
        s = ln.split("#", 1)[0].strip()
        if not s:
            continue
        tok = s.split()[0]
        if not re.fullmatch(r"[0-9]+", tok):
            continue
        uid = int(tok)
        if uid not in seen:
            seen.add(uid)
            ids.append(uid)
    return ids


def paused_ids(config_dir: str | Path | None = None) -> set[int]:
    """User ids temporarily excluded from inject/billing (still listed in membership)."""
    dirs: list[Path] = []
    env_dir = os.environ.get("IG_MULT_DIR") or ""
    if env_dir:
        dirs.append(Path(env_dir))
    if config_dir:
        dirs.append(Path(config_dir))
    dirs.append(Path("/etc/vpn-monitor"))
    for d in dirs:
        text = _read(d / "instagram-multiplier-paused.txt")
        if text:
            return set(parse_user_ids(text))
    return set()


def _read(path: Path) -> str:
    try:
        return path.read_text()
    except FileNotFoundError:
        return ""


def load_settings(config_dir: str | Path | None = None) -> Settings:
    dirs: list[Path] = []
    env_dir = os.environ.get("IG_MULT_DIR") or ""
    if env_dir:
        dirs.append(Path(env_dir))
    if config_dir:
        dirs.append(Path(config_dir))
    dirs.extend([Path("/tmp/ig-mult"), Path("/etc/vpn-monitor")])
    users_text = ""
    env_map: dict[str, str] = {}
    for d in dirs:
        ut = _read(d / "instagram-multiplier-users.txt")
        if ut and not users_text:
            users_text = ut
        for ln in _read(d / "instagram-multiplier.env").splitlines():
            s = ln.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            env_map.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    mult = float(env_map.get("INSTAGRAM_MULTIPLIER") or DEFAULT_MULTIPLIER)
    if mult <= 0:
        mult = DEFAULT_MULTIPLIER
    raw_dom = env_map.get("INSTAGRAM_DOMAINS") or ""
    domains = [x.strip() for x in raw_dom.split(",") if x.strip()] or list(DEFAULT_DOMAINS)
    all_ids = parse_user_ids(users_text)
    paused = paused_ids(config_dir)
    active_ids = [uid for uid in all_ids if uid not in paused]
    return Settings(user_ids=active_ids, multiplier=mult, domains=domains)


def _catch_all_rule(rules: list) -> tuple[int, dict | None]:
    """Locate the final catch-all rule that sends everything over the backhaul.

    Two layouts exist in the wild:
      * legacy: {inboundTag:[...], balancerTag:"backhaul"} (no domain)
      * pinned (vpn_path_lib.put_selector): {network:"tcp,udp", outboundTag:<TO-AMS-*>}
    Xray routing is first-match, so CAT rules MUST sit before this rule or they never fire.
    Returns (index, rule) or (len(rules), None) when not found.
    """
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            continue
        if any(r.get(k) for k in ("domain", "ip", "user", "port", "source", "sourcePort", "protocol", "attrs")):
            continue
        if r.get("balancerTag") == "backhaul" and r.get("inboundTag"):
            return i, r
        out = str(r.get("outboundTag") or "")
        if r.get("network") and out and out not in ("DIRECT", "BLOCK", "API") and not r.get("inboundTag"):
            return i, r
    return len(rules), None


def current_backhaul_tag(cfg: dict) -> str:
    bals = ((cfg.get("routing") or {}).get("balancers") or [{}])
    sel = (bals[0].get("selector") or []) if bals else []
    if sel:
        return str(sel[0])
    # Pinned layout: the live backhaul is whatever the catch-all rule points at.
    _, rule = _catch_all_rule((cfg.get("routing") or {}).get("rules") or [])
    if rule and rule.get("outboundTag"):
        return str(rule["outboundTag"])
    for ob in cfg.get("outbounds") or []:
        tag = ob.get("tag") or ""
        if tag.startswith("TO-AMS-"):
            return tag
    raise ValueError("no backhaul outbound to clone")


def _outbound_by_tag(cfg: dict, tag: str) -> dict | None:
    for ob in cfg.get("outbounds") or []:
        if ob.get("tag") == tag:
            return ob
    return None


def _strip_cat(cfg: dict) -> bool:
    changed = False
    obs = cfg.get("outbounds")
    if isinstance(obs, list):
        keep = [o for o in obs if not is_cat_tag(o.get("tag"))]
        if len(keep) != len(obs):
            cfg["outbounds"] = keep
            changed = True
    rules = ((cfg.get("routing") or {}).get("rules")) or []
    if isinstance(rules, list):
        keep_r = [
            r
            for r in rules
            if not is_cat_tag(r.get("outboundTag"))
            and not str(r.get("ruleTag") or "").startswith(TAG_PREFIX)
        ]
        if len(keep_r) != len(rules):
            cfg.setdefault("routing", {})["rules"] = keep_r
            changed = True
    return changed


def _catch_all_index(rules: list) -> int:
    return _catch_all_rule(rules)[0]


def inject_into_core(cfg: dict, settings: Settings | None = None) -> int:
    """Add CAT-instagram-u<id> outbounds+rules for selected users only.

    Clones the currently selected backhaul outbound (failover-safe if this runs
    on every export after the selector changes). Returns rule count added.
    """
    settings = settings or load_settings()
    _strip_cat(cfg)
    if not settings.user_ids:
        return 0
    src_tag = current_backhaul_tag(cfg)
    src = _outbound_by_tag(cfg, src_tag)
    if not src:
        raise ValueError(f"backhaul outbound {src_tag!r} missing")
    obs = cfg.setdefault("outbounds", [])
    rules = cfg.setdefault("routing", {}).setdefault("rules", [])
    insert_at, _ca = _catch_all_rule(rules)
    if _ca is None:
        import sys
        print("instagram_multiplier: WARNING no catch-all rule found; CAT rules appended last and may never match", file=sys.stderr)
    added = 0
    for uid in settings.user_ids:
        tag = tag_for(uid)
        clone = copy.deepcopy(src)
        clone["tag"] = tag
        obs.append(clone)
        rule = {
            "type": "field",
            "ruleTag": tag,
            "user": [str(uid)],
            "domain": list(settings.domains),
            "outboundTag": tag,
        }
        rules.insert(insert_at + added, rule)
        added += 1
    return added


def instagram_bytes(delta_map: dict[str, int], uid: int) -> int:
    """Bytes on CAT-instagram-u<id> (Instagram + configured adult hosts)."""
    tag = tag_for(uid)
    n = 0
    for direction in ("uplink", "downlink"):
        n += int(delta_map.get(f"outbound>>>{tag}>>>traffic>>>{direction}") or 0)
    return max(0, n)


def user_raw_bytes(delta_map: dict[str, int], uid: int) -> int:
    n = 0
    for direction in ("uplink", "downlink"):
        n += int(delta_map.get(f"user>>>{uid}>>>traffic>>>{direction}") or 0)
    return max(0, n)


def weighted_user_deltas(delta_map: dict[str, int], settings: Settings | None = None) -> dict[int, int]:
    """Map user id → bytes to add to used_traffic this interval."""
    settings = settings or load_settings()
    selected = set(settings.user_ids)
    uids: set[int] = set()
    for name in delta_map:
        parts = name.split(">>>")
        if len(parts) < 4 or parts[2] != "traffic":
            continue
        if parts[0] == "user":
            try:
                uids.add(int(parts[1]))
            except ValueError:
                continue
        elif parts[0] == "outbound" and is_cat_tag(parts[1]):
            try:
                uids.add(int(parts[1][len(TAG_PREFIX) :]))
            except ValueError:
                continue
    out: dict[int, int] = {}
    for uid in sorted(uids):
        raw = user_raw_bytes(delta_map, uid)
        if uid not in selected:
            if raw:
                out[uid] = raw
            continue
        ig = instagram_bytes(delta_map, uid)
        if raw:
            if ig > raw:
                ig = raw
            weighted = int(round((raw - ig) + ig * settings.multiplier))
        else:
            weighted = int(round(ig * settings.multiplier)) if ig else 0
        if weighted:
            out[uid] = weighted
    return out


STATS_EXTRA_RE = re.compile(r"u(\d+)_raw=(\d+)_(?:cat|ig)=(\d+)_w=(\d+)")
DEFAULT_STATS_LOG = Path("/var/log/vpn-path/stats.log")


@dataclass
class UserIntervalStats:
    raw: int = 0
    ig: int = 0
    weighted: int = 0

    @property
    def extra(self) -> int:
        return max(0, self.weighted - self.raw)


def format_bytes(n: int) -> str:
    b = float(max(0, int(n)))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if b < 1024.0 or unit == "TiB":
            if unit == "B":
                return f"{int(b)} {unit}"
            return f"{b:.1f} {unit}"
        b /= 1024.0
    return f"{b:.1f} TiB"


def parse_stats_line_extra(line: str) -> dict[int, UserIntervalStats]:
    out: dict[int, UserIntervalStats] = {}
    for m in STATS_EXTRA_RE.finditer(line):
        uid = int(m.group(1))
        raw, ig, weighted = (int(m.group(i)) for i in (2, 3, 4))
        st = out.setdefault(uid, UserIntervalStats())
        st.raw += raw
        st.ig += ig
        st.weighted += weighted
    return out


# --- stats aggregation -------------------------------------------------------
# stats.log lines are stamped in UTC ("2026-10-27T07:22:30Z"). Day buckets are
# computed in STATS_TZ (default Asia/Tehran) so "today" matches the operator's day.
# logrotate keeps only ~3 days, so per-day totals are also persisted in a small
# rollup file (idempotent; a day's entry is only replaced by a larger/complete one).
ROLLUP_PATH = Path(os.environ.get("IG_MULT_ROLLUP", "/var/lib/ig-mult-web/daily.json"))
_TS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z")
_scan_cache: dict = {}
_scan_lock = threading.Lock()
_rollup_lock = threading.Lock()


def stats_tz():
    name = os.environ.get("IG_STATS_TZ") or "Asia/Tehran"
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name)
    except Exception:  # noqa: BLE001
        return timezone.utc


def today_str() -> str:
    return datetime.now(stats_tz()).date().isoformat()


def stats_date_span(days: int) -> set[str]:
    return date_span(datetime.now(stats_tz()).date(), days)


def _line_day(line: str, tz) -> str | None:
    m = _TS_RE.match(line)
    if not m:
        return None
    y, mo, d, h, mi, sec = (int(x) for x in m.groups())
    try:
        dt = datetime(y, mo, d, h, mi, sec, tzinfo=timezone.utc)
    except ValueError:
        return None
    return dt.astimezone(tz).date().isoformat()


def _log_files(log_path: Path) -> list[Path]:
    """Current log plus rotated copies (.1, .2.gz, .3.gz ...)."""
    out = [log_path] if log_path.exists() else []
    out += sorted(
        (p for p in log_path.parent.glob(log_path.name + ".*") if re.fullmatch(r"\.\d+(\.gz)?", p.name[len(log_path.name):])),
        key=lambda p: int(re.match(r"\.(\d+)", p.name[len(log_path.name):]).group(1)),
    )
    return out


def _read_lines(p: Path) -> list[str]:
    try:
        if p.suffix == ".gz":
            with gzip.open(p, "rt", encoding="utf-8", errors="replace") as f:
                return f.read().splitlines()
        return p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _scan_logs(log_path: Path) -> dict[str, dict[int, "UserIntervalStats"]]:
    """{day: {uid: stats}} over every available log file (cached by mtime/size)."""
    tz = stats_tz()
    days: dict[str, dict[int, UserIntervalStats]] = {}
    seen_lines: set[tuple[str, int]] = set()  # guards against copytruncate overlap
    for p in _log_files(log_path):
        try:
            st = p.stat()
        except OSError:
            continue
        key = (str(p), st.st_mtime_ns, st.st_size, str(tz))
        with _scan_lock:
            cached = _scan_cache.get(str(p))
        if cached and cached[0] == key:
            part = cached[1]
        else:
            part = {}
            for line in _read_lines(p):
                day = _line_day(line, tz)
                if not day:
                    continue
                for uid, chunk in parse_stats_line_extra(line).items():
                    s_ = part.setdefault(day, {}).setdefault(uid, UserIntervalStats())
                    s_.raw += chunk.raw
                    s_.ig += chunk.ig
                    s_.weighted += chunk.weighted
            with _scan_lock:
                _scan_cache[str(p)] = (key, part)
        for day, users in part.items():
            dst = days.setdefault(day, {})
            for uid, c in users.items():
                d_ = dst.setdefault(uid, UserIntervalStats())
                d_.raw += c.raw
                d_.ig += c.ig
                d_.weighted += c.weighted
    return days


def _total(day_map: dict) -> int:
    return sum(v.raw + v.weighted for v in day_map.values())


def _load_rollup() -> dict[str, dict[int, "UserIntervalStats"]]:
    try:
        raw = json.loads(ROLLUP_PATH.read_text())
    except (OSError, ValueError):
        return {}
    out: dict[str, dict[int, UserIntervalStats]] = {}
    for day, users in (raw.get("days") or {}).items():
        for uid, v in (users or {}).items():
            try:
                out.setdefault(day, {})[int(uid)] = UserIntervalStats(
                    raw=int(v[0]), ig=int(v[1]), weighted=int(v[2])
                )
            except (TypeError, ValueError, IndexError):
                continue
    return out


def update_rollup(log_path: Path | str = DEFAULT_STATS_LOG, keep_days: int = 120) -> None:
    """Persist per-day totals from the logs. Safe to call repeatedly."""
    with _rollup_lock:
        scanned = _scan_logs(Path(log_path))
        have = _load_rollup()
        changed = False
        for day, users in scanned.items():
            if day not in have or _total(users) > _total(have[day]):
                have[day] = users
                changed = True
        if not changed:
            return
        cutoff = (datetime.now(stats_tz()).date() - timedelta(days=keep_days)).isoformat()
        payload = {
            "tz": str(stats_tz()),
            "days": {
                d: {str(u): [v.raw, v.ig, v.weighted] for u, v in us.items()}
                for d, us in sorted(have.items())
                if d >= cutoff
            },
        }
        ROLLUP_PATH.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(ROLLUP_PATH.parent), prefix=".daily-", suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, separators=(",", ":"))
        os.chmod(tmp, 0o600)
        os.replace(tmp, ROLLUP_PATH)


def stats_coverage(log_path: Path | str = DEFAULT_STATS_LOG) -> str | None:
    """Earliest day for which any data (logs or rollup) exists."""
    days = set(_scan_logs(Path(log_path))) | set(_load_rollup())
    return min(days) if days else None


def aggregate_ig_stats(
    log_path: Path | str = DEFAULT_STATS_LOG,
    user_ids: list[int] | None = None,
    *,
    dates: set[str] | None = None,
) -> dict[int, UserIntervalStats]:
    """Sum u<id>_raw/_ig/_w for the given local days (STATS_TZ).

    Uses the live log + rotated logs + persisted daily rollup (whichever is more
    complete per day).
    """
    path = Path(log_path)
    selected = set(user_ids or [])
    per_day = _scan_logs(path)
    roll = _load_rollup()
    out: dict[int, UserIntervalStats] = {}
    for day in set(per_day) | set(roll):
        if dates and day not in dates:
            continue
        a, b = per_day.get(day, {}), roll.get(day, {})
        src = a if _total(a) >= _total(b) else b
        for uid, c in src.items():
            if selected and uid not in selected:
                continue
            st = out.setdefault(uid, UserIntervalStats())
            st.raw += c.raw
            st.ig += c.ig
            st.weighted += c.weighted
    return out


def ig_extra_bytes(ig_bytes: int, multiplier: float) -> int:
    if ig_bytes <= 0 or multiplier <= 1:
        return 0
    return int(round(ig_bytes * (multiplier - 1.0)))


def date_span(end: date, days: int) -> set[str]:
    n = max(1, int(days))
    return {(end - timedelta(days=i)).isoformat() for i in range(n)}


def _demo() -> None:
    cfg = {
        "outbounds": [
            {"tag": "TO-AMS-CF", "protocol": "vless", "settings": {"vnext": [{"address": "cdn.example"}]}},
            {"tag": "DIRECT", "protocol": "freedom"},
        ],
        "routing": {
            "balancers": [{"tag": "backhaul", "selector": ["TO-AMS-CF"]}],
            "rules": [
                {"type": "field", "inboundTag": ["API"], "outboundTag": "API"},
                {
                    "type": "field",
                    "inboundTag": ["VLESS-REALITY", "VLESS-VISION"],
                    "balancerTag": "backhaul",
                },
            ],
        },
    }
    n = inject_into_core(cfg, Settings(user_ids=[2, 9], multiplier=1.5))
    assert n == 2
    tags = [o["tag"] for o in cfg["outbounds"]]
    assert tags.count("CAT-instagram-u2") == 1
    assert "CAT-instagram-u9" in tags
    assert "CAT-instagram-u4" not in tags
    assert cfg["outbounds"][-2]["settings"]["vnext"][0]["address"] == "cdn.example"
    catch = cfg["routing"]["rules"][-1]
    assert catch.get("balancerTag") == "backhaul"
    assert cfg["routing"]["rules"][-3]["outboundTag"] == "CAT-instagram-u2"
    d = {
        "user>>>2>>>traffic>>>uplink": 100,
        "user>>>2>>>traffic>>>downlink": 900,
        "user>>>4>>>traffic>>>uplink": 50,
        "user>>>4>>>traffic>>>downlink": 50,
        "outbound>>>CAT-instagram-u2>>>traffic>>>uplink": 10,
        "outbound>>>CAT-instagram-u2>>>traffic>>>downlink": 90,
    }
    w = weighted_user_deltas(d, Settings(user_ids=[2], multiplier=1.5))
    assert w[2] == 1050  # (1000-100) + 100*1.5
    assert w[4] == 100
    d_cat_only = {
        "outbound>>>CAT-instagram-u2>>>traffic>>>uplink": 10,
        "outbound>>>CAT-instagram-u2>>>traffic>>>downlink": 90,
    }
    w_cat = weighted_user_deltas(d_cat_only, Settings(user_ids=[2], multiplier=1.5))
    assert w_cat[2] == 150
    cfg["routing"]["balancers"][0]["selector"] = ["TO-AMS-XHTTP"]
    cfg["outbounds"].insert(0, {"tag": "TO-AMS-XHTTP", "protocol": "vless", "settings": {"addr": "x"}})
    inject_into_core(cfg, Settings(user_ids=[2]))
    cat = _outbound_by_tag(cfg, "CAT-instagram-u2")
    assert cat and cat.get("settings", {}).get("addr") == "x"
    inject_into_core(cfg, Settings(user_ids=[]))
    assert not any(is_cat_tag(o.get("tag")) for o in cfg["outbounds"])
    print("instagram_multiplier self-test ok")


if __name__ == "__main__":
    _demo()
