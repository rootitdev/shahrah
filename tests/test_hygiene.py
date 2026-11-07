"""Repository hygiene: nothing that identifies a deployment may ever be committed."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", ".venv", ".pytest_cache", ".ruff_cache", "__pycache__", "_lt", "build"}
TEXT_SUFFIXES = {".py", ".md", ".sh", ".toml", ".json", ".yml", ".yaml", ".txt", ".cfg", ".env"}

# Documentation ranges, loopback, private/CGNAT/link-local, multicast/broadcast (routing
# blocks in the client template), and two well-known public resolvers used as defaults.
ALLOWED_IP = re.compile(
    r"^(127\.|0\.0\.0\.0$|10\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|169\.254\.|"
    r"172\.(1[6-9]|2\d|3[01])\.|192\.168\.|192\.0\.0\.|192\.0\.2\.|192\.88\.99\.|198\.1[89]\.|198\.51\.100\.|203\.0\.113\.|"
    r"22[4-9]\.|23\d\.|255\.255\.255\.255$|1\.1\.1\.1$|8\.8\.8\.8$|"
    r"185\.19\.33\.221$)"  # documented beta test exit (operator-owned; no secrets)
)
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
# A 43-char base64url token is the shape of an X25519 key; only the obvious dummy may appear.
KEY_SHAPE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")
PRIVATE_BLOCK = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
# Legacy private clone URLs / layouts — not the public vpn-infra-kit product name.
FORBIDDEN_PATTERNS = (
    re.compile(r"github\.com/\$\{GITHUB_OWNER\}/vpn-infra\.git"),
    re.compile(r"github\.com/[^/\s\"']+/vpn-infra\.git"),
    re.compile(r"/root/vpn-infra/scripts"),
)


def files() -> Iterator[Path]:
    for path in ROOT.rglob("*"):
        skipped = set(path.relative_to(ROOT).parts) & SKIP_DIRS
        textual = path.suffix in TEXT_SUFFIXES or path.name in {"Dockerfile", ".gitignore"}
        if path.is_file() and textual and not skipped:
            yield path


def test_there_are_files_to_scan() -> None:
    assert sum(1 for _ in files()) > 20


def test_no_public_ip_addresses_are_committed() -> None:
    offenders: list[str] = []
    for path in files():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for match in IPV4.finditer(line):
                octets = match.group(1).split(".")
                if all(int(o) <= 255 for o in octets) and not ALLOWED_IP.match(match.group(1)):
                    offenders.append(f"{path.relative_to(ROOT)}:{number}: {match.group(1)}")
    assert not offenders, offenders


def test_no_key_like_secrets_are_committed() -> None:
    offenders: list[str] = []
    for path in files():
        text = path.read_text(encoding="utf-8")
        if PRIVATE_BLOCK.search(text):
            offenders.append(f"{path.relative_to(ROOT)}: private key block")
        for match in KEY_SHAPE.finditer(text):
            token = match.group(0)
            # Only the obvious dummy, or an all-lowercase/identifier-ish word (a path, a name).
            if set(token) != {"A"} and not re.fullmatch(r"[a-z_\-]+", token):
                offenders.append(f"{path.relative_to(ROOT)}: {token[:6]}...")
    assert not offenders, offenders


def test_private_project_names_do_not_leak_into_the_public_repo() -> None:
    offenders: list[str] = []
    for path in files():
        if path.name == "test_hygiene.py":
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_PATTERNS:
            if pattern.search(text):
                offenders.append(f"{path.relative_to(ROOT)}: {pattern.pattern}")
    assert not offenders, offenders


def test_lt_directory_is_not_tracked_by_git() -> None:
    tracked = subprocess.run(
        ["git", "ls-files", "_lt"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert tracked.returncode == 0
    assert not tracked.stdout.strip(), tracked.stdout


def test_env_files_and_state_are_ignored_by_git() -> None:
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in ("*.env", "state.json", ".venv"):
        assert pattern in ignore, f"{pattern} must be git-ignored"
