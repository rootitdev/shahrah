#!/usr/bin/env bash
# Build sanitized beta release tarballs + SHA256 manifest (no _lt, no secrets).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SHA="$(git rev-parse HEAD)"
SHORT="$(git rev-parse --short HEAD)"
OUT="${1:-/opt/cursor/artifacts}"
KIT_ZIP="${KIT_ZIP:-/home/ubuntu/.cursor/projects/workspace/uploads/vpn-infra-kit-audit_12a1.zip}"
STAGE="/tmp/shahrah-beta-build-$$"
REL="shahrah-beta-${SHORT}"
mkdir -p "$OUT" "$STAGE/$REL"

tar -C "$ROOT" \
  --exclude='.git' --exclude='_lt' --exclude='.venv' --exclude='__pycache__' \
  --exclude='.pytest_cache' --exclude='.ruff_cache' \
  -cf "$STAGE/${REL}.tar" .

if [[ -f "$KIT_ZIP" ]]; then
  unzip -q -o "$KIT_ZIP" -d "$STAGE/kit-src"
  python3 "$ROOT/contrib/vpn-infra-kit-remediation/remediate_kit.py" "$STAGE/kit-src/vpn-infra-kit"
  mkdir -p "$STAGE/${REL}-kit-patched"
  tar -C "$STAGE/kit-src/vpn-infra-kit" -cf - . | tar -C "$STAGE/${REL}-kit-patched" -xf -
  find "$STAGE/${REL}-kit-patched" -name '*.sh' -exec bash -n {} \;
fi

printf '%s\nbuilt_utc=%s\n' "$SHA" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$STAGE/RELEASE.meta"

gzip -c "$STAGE/${REL}.tar" >"$OUT/${REL}.tar.gz"
rm -f "$STAGE/${REL}.tar"
if [[ -d "$STAGE/${REL}-kit-patched" ]]; then
  tar -C "$STAGE" -czf "$OUT/${REL}-vpn-infra-kit-patched.tar.gz" "${REL}-kit-patched"
fi

(
  cd "$OUT"
  sha256sum "${REL}.tar.gz" >"${REL}.sha256.manifest"
  [[ -f "${REL}-vpn-infra-kit-patched.tar.gz" ]] && sha256sum "${REL}-vpn-infra-kit-patched.tar.gz" >>"${REL}.sha256.manifest"
)
cat >"$OUT/${REL}-HANDOFF.txt" <<EOF
commit=$SHA
shahrah_tarball=${REL}.tar.gz
kit_tarball=${REL}-vpn-infra-kit-patched.tar.gz (optional; not for Germany-only beta)
recipe=scripts/package-beta-release.sh
germany_beta=deploy/beta/germany-exit-install.sh REALITY_HOST=reality.bluelark.ir
rollback=deploy/rollback-install.sh
control_plane=shahrah brain only (do not enable vpn-infra-kit failover on same host)
panels_beta=do not install settle/ig; SHAHRAH_BETA=1 if using install-panels.sh
iran_phase2=blocked for full kit on 1GB; relay-only later if needed
manifest=${REL}.sha256.manifest
EOF

rm -rf "$STAGE"
echo "Wrote $OUT/${REL}.tar.gz"
