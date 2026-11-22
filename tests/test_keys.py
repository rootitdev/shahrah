from __future__ import annotations

import subprocess

import pytest

from shahrah import keys
from shahrah.models import validate_short_id, validate_x25519_key


def test_rfc7748_scalar_multiplication_vectors() -> None:
    # RFC 7748 section 5.2, first test vector.
    scalar = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    expected = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    assert keys.x25519(scalar, u).hex() == expected


def test_rfc7748_diffie_hellman_agreement() -> None:
    # RFC 7748 section 6.1: Alice and Bob derive the same shared secret.
    alice = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert keys.public_from_private_bytes(alice).hex() == (
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    )
    assert keys.x25519(alice, keys.public_from_private_bytes(bob)).hex() == shared
    assert keys.x25519(bob, keys.public_from_private_bytes(alice)).hex() == shared


def test_generated_keys_pass_model_validation_and_are_unique() -> None:
    first, second = keys.generate_keypair(), keys.generate_keypair()
    assert first != second
    for private, public in (first, second):
        assert validate_x25519_key(private, "private") == private
        assert validate_x25519_key(public, "public") == public
        assert keys.public_from_private(private) == public


def test_generated_short_id_is_valid() -> None:
    for size in (1, 4, 8):
        assert validate_short_id(keys.generate_short_id(size))
    with pytest.raises(ValueError, match="1-8"):
        keys.generate_short_id(9)


def test_public_key_matches_real_xray(xray_bin: str) -> None:
    private, public = keys.generate_keypair()
    out = subprocess.run(
        [xray_bin, "x25519", "-i", private], capture_output=True, text=True, check=True
    ).stdout
    assert public in out
