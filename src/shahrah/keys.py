"""X25519 key generation for REALITY, in pure standard-library Python (RFC 7748).

Generating keys here means ``shahrah`` can initialise a node without calling out to a
binary, and the algorithm is cross-checked against ``xray x25519`` in the test-suite.
Keys use the unpadded URL-safe base64 form Xray expects (43 characters).
"""

from __future__ import annotations

import base64
import secrets
import uuid as uuid_lib

_P = 2**255 - 19
_A24 = 121665
_BASE_POINT = 9


def _clamp(scalar: bytes) -> bytes:
    data = bytearray(scalar)
    data[0] &= 248
    data[31] &= 127
    data[31] |= 64
    return bytes(data)


def _ladder(scalar: bytes, u: int) -> int:
    """Montgomery ladder from RFC 7748 section 5 (``scalar`` must already be clamped)."""
    k = int.from_bytes(scalar, "little")
    x1, x2, z2, x3, z3 = u, 1, 0, u, 1
    swap = 0
    for bit in range(254, -1, -1):
        k_t = (k >> bit) & 1
        swap ^= k_t
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return x2 * pow(z2, _P - 2, _P) % _P


def x25519(scalar: bytes, u_bytes: bytes) -> bytes:
    """RFC 7748 ``X25519(k, u)`` on 32-byte little-endian inputs."""
    if len(scalar) != 32 or len(u_bytes) != 32:
        raise ValueError("X25519 inputs must be 32 bytes")
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    return _ladder(_clamp(scalar), u).to_bytes(32, "little")


def public_from_private_bytes(private: bytes) -> bytes:
    return x25519(private, _BASE_POINT.to_bytes(32, "little"))


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def generate_keypair() -> tuple[str, str]:
    """Return a fresh ``(private, public)`` REALITY keypair as Xray-formatted strings."""
    private = _clamp(secrets.token_bytes(32))
    return _b64(private), _b64(public_from_private_bytes(private))


def public_from_private(private_b64: str) -> str:
    """Derive the public key for an existing REALITY private key."""
    raw = _unb64(private_b64)
    if len(raw) != 32:
        raise ValueError("private key must decode to 32 bytes")
    return _b64(public_from_private_bytes(raw))


def generate_short_id(nbytes: int = 8) -> str:
    """Random REALITY short id (hex). 8 bytes is the maximum length Xray allows."""
    if not 1 <= nbytes <= 8:
        raise ValueError("short id must be 1-8 bytes")
    return secrets.token_hex(nbytes)


def generate_uuid() -> str:
    return str(uuid_lib.uuid4())
