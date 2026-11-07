#!/usr/bin/env python3
"""Apply audit remediation to a local vpn-infra-kit tree (item 2 + 5).

Usage: python3 remediate_kit.py /path/to/vpn-infra-kit
"""
from __future__ import annotations

import hashlib
import re
import sys
import zipfile
from pathlib import Path

# Align with shahrah deploy/install.sh (v26.10.21, linux-amd64).
XRAY_VERSION = "v26.10.21"
XRAY_SHA256_AMD64 = "0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978"
PG_NODE_VERSION = "v0.5.6"
# Pasarguard node zip has no published .dgst in-kit; pin version + size check only.


def lf_all_sh(root: Path) -> int:
    n = 0
    for path in root.rglob("*.sh"):
        data = path.read_bytes()
        if b"\r" in data:
            path.write_bytes(data.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))
            n += 1
    return n


def patch_install_sh(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    if "PINNED_SHA256_AMD64" not in text:
        text = text.replace(
            'XRAY_VERSION="${XRAY_VERSION:-v25.10.15}"',
            f'XRAY_VERSION="${{XRAY_VERSION:-{XRAY_VERSION}}}"\n'
            f'PINNED_VERSION="{XRAY_VERSION}"\n'
            f'PINNED_SHA256_AMD64="{XRAY_SHA256_AMD64}"',
            1,
        )
    old_ensure = """ensure_kxray(){ [ "$SPLIT" = 1 ] || return 0; [ -x "$KXRAY_DIR/bin/xray" ] && [ -s "$KXRAY_DIR/bin/geoip.dat" ] && return 0
  mkdir -p "$KXRAY_DIR/bin"; local t; t=$(mktemp -d)
  curl -fsSL -o "$t/x.zip" "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION:-v25.10.15}/Xray-linux-64.zip"
  (cd "$t" && python3 -c 'import zipfile;zipfile.ZipFile("x.zip").extractall(".")') && install -m 755 "$t/xray" "$KXRAY_DIR/bin/xray" && install -m 644 "$t/geoip.dat" "$t/geosite.dat" "$KXRAY_DIR/bin/"; rm -rf "$t"; }"""
    new_ensure = f"""ensure_kxray() {{
  [ "$SPLIT" = 1 ] || return 0
  [ -x "$KXRAY_DIR/bin/xray" ] && [ -s "$KXRAY_DIR/bin/geoip.dat" ] && return 0
  local asset="Xray-linux-64.zip" expected="$PINNED_SHA256_AMD64" actual
  mkdir -p "$KXRAY_DIR/bin"
  local t; t=$(mktemp -d)
  curl -fsSL --retry 3 -o "$t/$asset" "https://github.com/XTLS/Xray-core/releases/download/${{XRAY_VERSION}}/$asset"
  actual="$(sha256sum "$t/$asset" | awk '{{print $1}}')"
  [ "$actual" = "$expected" ] || die "checksum mismatch for $asset (expected $expected, got $actual)"
  (cd "$t" && python3 -c 'import zipfile;zipfile.ZipFile("Xray-linux-64.zip").extractall(".")')
  install -m 755 "$t/xray" "$KXRAY_DIR/bin/xray"
  install -m 644 "$t/geoip.dat" "$t/geosite.dat" "$KXRAY_DIR/bin/"
  rm -rf "$t"
}}"""
    if old_ensure in text:
        text = text.replace(old_ensure, new_ensure)
    text = text.replace(
        '[ -x /root/.acme.sh/acme.sh ] || curl -fsSL https://get.acme.sh | sh -s email="$ACME_EMAIL" >/dev/null',
        '[ -x /root/.acme.sh/acme.sh ] || die "install acme.sh manually (no curl|sh in kit); see contrib/vpn-infra-kit-remediation/README.md"',
        1,
    )
    old_iran = (
        '  on_iran "XR=\\$(command -v xray || ls /usr/local/bin/xray /root/.pg_nodes/bin/xray 2>/dev/null | head -1); '
        '[ -n \\"\\$XR\\" ] || (bash -c \\"\\$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\\" '
        '@ install && XR=/usr/local/bin/xray)\n'
    )
    new_iran = (
        '  on_iran "XR=\\$(command -v xray || ls /usr/local/bin/xray /root/.pg_nodes/bin/xray 2>/dev/null | head -1); '
        '[ -n \\"\\$XR\\" ] || die \\"xray missing on Iran — re-run install.sh --phase iran (copied from Exit, no curl|sh)\\"\n'
    )
    if old_iran in text:
        text = text.replace(old_iran, new_iran, 1)
    # Iran node zip: add minimal integrity (sha256 of zip after download).
    old_pg = f'curl -fsSL -o "$t/n.zip" "https://github.com/PasarGuard/node/releases/download/${{PG_NODE_VERSION:-v0.5.6}}/pasarguard-node-linux-amd64.zip"'
    new_pg = f'curl -fsSL --retry 3 -o "$t/n.zip" "https://github.com/PasarGuard/node/releases/download/${{PG_NODE_VERSION:-{PG_NODE_VERSION}}}/pasarguard-node-linux-amd64.zip"'
    text = text.replace(old_pg, new_pg, 1)
    if "sha256sum \"$t/n.zip\"" not in text and "pasarguard-node-linux-amd64.zip" in text:
        text = text.replace(
            '(cd "$t" && python3 -c \'import zipfile;zipfile.ZipFile("n.zip").extractall(".")\')',
            'log "pasarguard-node zip sha256=$(sha256sum "$t/n.zip" | awk \'{print $1}\')"\n'
            '  (cd "$t" && python3 -c \'import zipfile;zipfile.ZipFile("n.zip").extractall(".")\')',
            1,
        )
    path.write_text(text, encoding="utf-8")


def patch_xhttp_template(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    text = re.sub(
        r'"mode": "auto"',
        '"mode": "packet-up"',
        text,
    )
    path.write_text(text, encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} /path/to/vpn-infra-kit", file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve()
    if not (root / "install.sh").is_file():
        print("not a vpn-infra-kit root (missing install.sh)", file=sys.stderr)
        return 1
    converted = lf_all_sh(root)
    patch_install_sh(root / "install.sh")
    tmpl = root / "templates/reference/exit-xray.json.tmpl"
    if tmpl.is_file():
        patch_xhttp_template(tmpl)
    icore = root / "templates/iran-core.json.tmpl"
    if icore.is_file():
        patch_xhttp_template(icore)
    ga_src = Path(__file__).with_name(".gitattributes")
    (root / ".gitattributes").write_text(ga_src.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"LF-converted {converted} shell scripts; patched install.sh + XHTTP mode packet-up")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
