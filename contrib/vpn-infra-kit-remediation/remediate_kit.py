#!/usr/bin/env python3
"""Apply audit + beta remediation to a local vpn-infra-kit tree.

Usage: python3 remediate_kit.py /path/to/vpn-infra-kit
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

XRAY_VERSION = "v26.10.21"
XRAY_SHA256_AMD64 = "0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978"
PG_NODE_VERSION = "v0.5.6"
HY2_VERSION = "app/v2.13.0"
HY2_SHA256_AMD64 = "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691"


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
    old_pg = (
        'curl -fsSL -o "$t/n.zip" '
        '"https://github.com/PasarGuard/node/releases/download/${PG_NODE_VERSION:-v0.5.6}/pasarguard-node-linux-amd64.zip"'
    )
    new_pg = (
        f'curl -fsSL --retry 3 -o "$t/n.zip" '
        f'"https://github.com/PasarGuard/node/releases/download/${{PG_NODE_VERSION:-{PG_NODE_VERSION}}}/pasarguard-node-linux-amd64.zip"'
    )
    text = text.replace(old_pg, new_pg, 1)
    if 'sha256sum "$t/n.zip"' not in text:
        text = text.replace(
            '(cd "$t" && python3 -c \'import zipfile;zipfile.ZipFile("n.zip").extractall(".")\')',
            'log "pasarguard-node zip sha256=$(sha256sum "$t/n.zip" | awk \'{print $1}\')"\n'
            '  (cd "$t" && python3 -c \'import zipfile;zipfile.ZipFile("n.zip").extractall(".")\')',
            1,
        )
    if "SHAHRAH_WITH_KIT_FAILOVER" not in text:
        text = text.replace(
            "phase_preflight(){",
            'phase_preflight(){\n  [ "${SHAHRAH_BRAIN_ACTIVE:-0}" = 1 ] && die "SHAHRAH_BRAIN_ACTIVE=1 — pick kit failover OR shahrah-brain, not both (docs/CONTROL-PLANE.md)"',
            1,
        )
    path.write_text(text, encoding="utf-8")


def patch_bootstrap_iran(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        'bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install',
        'echo "xray must be supplied under /root/.pg_nodes/bin — no curl|sh install" >&2; exit 1',
        1,
    )
    hy2_old = 'curl -fsSL https://get.hy2.sh | bash'
    hy2_new = f"""if command -v hysteria >/dev/null; then :; else
    echo "install hysteria manually or copy to /root/.pg_nodes/bin/hysteria" >&2
    echo "pinned ref: {HY2_VERSION} sha256:{HY2_SHA256_AMD64}" >&2
    exit 1
  fi"""
    text = text.replace(
        "  else\n    curl -fsSL https://get.hy2.sh | bash\n  fi",
        f"  else\n{hy2_new}\n  fi",
        1,
    )
    path.write_text(text, encoding="utf-8")


def patch_python_render(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    text = text.replace('"mode": "auto"', '"mode": "packet-up"')
    path.write_text(text, encoding="utf-8")


def patch_xhttp_template(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    text = re.sub(r'"mode": "auto"', '"mode": "packet-up"', text)
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
    boot = root / "scripts/bootstrap-iran.sh"
    if boot.is_file():
        patch_bootstrap_iran(boot)
    for py in (
        root / "scripts/render_exit_configs.py",
        root / "scripts/render_iran_configs.py",
    ):
        if py.is_file():
            patch_python_render(py)
    for tmpl in (
        root / "templates/reference/exit-xray.json.tmpl",
        root / "templates/iran-core.json.tmpl",
    ):
        if tmpl.is_file():
            patch_xhttp_template(tmpl)
    ga_src = Path(__file__).with_name(".gitattributes")
    (root / ".gitattributes").write_text(ga_src.read_text(encoding="utf-8"), encoding="utf-8")
    print(
        f"LF-converted {converted} shell scripts; patched install/bootstrap/render/templates"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
