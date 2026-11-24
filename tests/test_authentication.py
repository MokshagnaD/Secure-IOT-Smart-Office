"""
tests/test_authentication.py
Tests for device authentication, ECC key management, and digital signatures.
"""

import pytest
from pathlib import Path
from crypto.key_management import generate_ecc_keypair, wrap_session_key, unwrap_session_key
from crypto.encryption import generate_key
from crypto.signatures import generate_signature, verify_signature
from crypto.device_registry import (
    AUTHORIZED_DEVICE_IDS,
    ensure_all_devices_registered,
    load_device_public_key,
    load_device_private_key,
    is_registered,
)


@pytest.fixture(scope="module", autouse=True)
def _register_devices():
    """Ensure registered device keypairs exist even on a fresh repository clone."""
    ensure_all_devices_registered()


# ── Device authentication ─────────────────────────────────────────────────────

def test_authorized_device_accepted():
    """[TEST] Known device IDs must be in the authorized set."""
    for device_id in ["temperature_01", "motion_01", "door_01"]:
        assert device_id in AUTHORIZED_DEVICE_IDS
    print("\n[TEST] Authorized devices accepted: PASS")


def test_unauthorized_device_rejected():
    """[TEST] Unknown device ID must not be in the authorized set."""
    assert "unknown_device_99" not in AUTHORIZED_DEVICE_IDS
    assert "hacker_device"     not in AUTHORIZED_DEVICE_IDS
    print("[TEST] Unauthorized device rejected: PASS")


def test_registered_devices_have_keys_on_disk():
    """[TEST] All authorized devices must have public keys registered on disk."""
    for device_id in AUTHORIZED_DEVICE_IDS:
        assert is_registered(device_id), \
            f"Device '{device_id}' has no registered public key. Run: python -m crypto.device_registry register-all"
    print("[TEST] All devices have registered keys: PASS")


def test_server_loads_trusted_public_key():
    """[TEST] Server must be able to load the trusted public key for each device."""
    for device_id in AUTHORIZED_DEVICE_IDS:
        key = load_device_public_key(device_id)
        assert key is not None
    print("[TEST] Trusted public key loading: PASS")


def test_invalid_device_public_key_rejected():
    """
    [TEST] A rogue device sending a valid device_id but signing with a
    different (unregistered) private key must fail signature verification.

    This is the critical fix: the server uses the REGISTRY key, not the
    client-supplied key. So even if an attacker knows a valid device_id,
    they cannot forge a valid signature without the registered private key.
    """
    # Attacker generates their own key pair
    attacker_private, _ = generate_ecc_keypair()

    # Attacker claims to be temperature_01 and signs with their own key
    message   = b'{"device_id":"temperature_01","value":28.5}'
    signature = generate_signature(attacker_private, message)

    # Server loads the TRUSTED public key from the registry
    trusted_public_key = load_device_public_key("temperature_01")

    # Verification must FAIL — attacker's signature won't match the trusted key
    assert verify_signature(trusted_public_key, message, signature) is False
    print("[TEST] Invalid (unregistered) device public key rejected: PASS")


def test_server_restart_preserves_device_keys():
    """
    [TEST] Device public keys must persist across server restarts.
    Simulated by loading the key twice and confirming it's the same key.
    """
    key1 = load_device_public_key("temperature_01")
    key2 = load_device_public_key("temperature_01")
    from cryptography.hazmat.primitives import serialization
    pem1 = key1.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    pem2 = key2.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert pem1 == pem2, "Public key must be identical across loads (persistent)"
    print("[TEST] Device keys persist across server restarts: PASS")


# ── ECC key wrap / unwrap ─────────────────────────────────────────────────────

def test_session_key_wrap_unwrap():
    """[TEST] Session key wrapped with ECC public key must unwrap to original."""
    private_key, public_key = generate_ecc_keypair()
    session_key = generate_key()
    wrapped     = wrap_session_key(session_key, public_key)
    recovered   = unwrap_session_key(wrapped, private_key)
    assert recovered == session_key
    print("[TEST] ECC session key wrap/unwrap: PASS")


def test_wrong_private_key_fails():
    """[TEST] Unwrapping with a different private key must fail."""
    _, public_key    = generate_ecc_keypair()
    wrong_private, _ = generate_ecc_keypair()
    session_key      = generate_key()
    wrapped          = wrap_session_key(session_key, public_key)
    with pytest.raises(Exception):
        unwrap_session_key(wrapped, wrong_private)
    print("[TEST] Wrong ECC private key rejection: PASS")


# ── Digital signatures ────────────────────────────────────────────────────────

def test_valid_signature_passes():
    """[TEST] Signature over original message must verify successfully."""
    private_key, public_key = generate_ecc_keypair()
    message   = b'{"device_id":"temperature_01","value":28.5}'
    signature = generate_signature(private_key, message)
    assert verify_signature(public_key, message, signature) is True
    print("[TEST] Valid signature verification: PASS")


def test_modified_message_fails():
    """[TEST] Signature must fail when message is modified (integrity)."""
    private_key, public_key = generate_ecc_keypair()
    original  = b'{"device_id":"temperature_01","value":28.5}'
    signature = generate_signature(private_key, original)
    tampered  = b'{"device_id":"temperature_01","value":99.9}'
    assert verify_signature(public_key, tampered, signature) is False
    print("[TEST] Modified message signature rejection: PASS")


def test_wrong_public_key_fails():
    """[TEST] Verifying with a different public key must fail."""
    private_key, _      = generate_ecc_keypair()
    _, other_public_key = generate_ecc_keypair()
    message   = b"sensor data"
    signature = generate_signature(private_key, message)
    assert verify_signature(other_public_key, message, signature) is False
    print("[TEST] Wrong public key rejection: PASS")


def test_registered_device_signature_roundtrip():
    """
    [TEST] A message signed with the registered private key must verify
    successfully against the registered public key (as the server would do).
    """
    device_id   = "temperature_01"
    private_key = load_device_private_key(device_id)
    public_key  = load_device_public_key(device_id)
    message     = b'{"device_id":"temperature_01","value":22.1}'
    signature   = generate_signature(private_key, message)
    assert verify_signature(public_key, message, signature) is True
    print("[TEST] Registered device signature roundtrip: PASS")
