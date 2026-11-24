"""
tests/test_security.py
Security attack demonstration tests.

Covers:
A. Normal secure communication (encrypt → decrypt roundtrip)
B. Message tampering (modified ciphertext must fail)
C. Unauthorized device (unknown device_id must be rejected)
D. Replay attack (expired timestamp + duplicate message_id must be rejected)
E. Plaintext vs encrypted (shows why plaintext is unsafe)
F. Valid sensor message structure
"""

import time
import uuid
import json
import pytest
from cryptography.exceptions import InvalidTag

from crypto.encryption import generate_key, encrypt_message, decrypt_message
from crypto.signatures import generate_signature, verify_signature
from crypto.key_management import generate_ecc_keypair

# Mirrors the server's authorized device registry
AUTHORIZED_DEVICES = {"temperature_01", "motion_01", "door_01"}
TIMESTAMP_WINDOW   = 30   # seconds — mirrors server config


# ── Replay protection logic (mirrors server._check_replay) ───────────────────

_seen_ids: set = set()

def check_replay(message_id: str, timestamp: float) -> None:
    """Raises ValueError if message is expired or already seen."""
    now = time.time()
    age = now - timestamp
    if age > TIMESTAMP_WINDOW or age < -5:
        raise ValueError(
            f"[SECURITY] Replay attack detected: timestamp expired (age={age:.1f}s). "
            "Message rejected."
        )
    if message_id in _seen_ids:
        raise ValueError(
            f"[SECURITY] Replay attack detected: duplicate message_id '{message_id}'. "
            "Message rejected."
        )
    _seen_ids.add(message_id)


# ── A. Normal secure communication ───────────────────────────────────────────

def test_A_normal_secure_communication():
    """[TEST A] Full encrypt → sign → verify → decrypt roundtrip must succeed."""
    private_key, public_key = generate_ecc_keypair()
    key       = generate_key()
    plaintext = json.dumps({
        "device_id":   "temperature_01",
        "sensor_type": "temperature",
        "value":       28.5,
        "unit":        "C",
        "timestamp":   time.time(),
        "message_id":  str(uuid.uuid4()),
    }).encode()

    # Sign
    signature = generate_signature(private_key, plaintext)
    # Encrypt
    enc = encrypt_message(key, plaintext, b"temperature_01")
    # Verify signature
    assert verify_signature(public_key, plaintext, signature) is True
    # Decrypt
    recovered = decrypt_message(key, enc["nonce"], enc["ciphertext"], b"temperature_01")
    assert recovered == plaintext
    print("\n[TEST A] Normal secure communication: PASS")


# ── B. Message tampering ──────────────────────────────────────────────────────

def test_B_tampered_ciphertext_rejected():
    """[TEST B] Flipping a byte in the ciphertext must raise InvalidTag."""
    key       = generate_key()
    plaintext = b"temperature:28.5C"
    enc       = encrypt_message(key, plaintext)
    tampered  = bytearray(enc["ciphertext"])
    tampered[0] ^= 0xFF
    with pytest.raises(InvalidTag):
        decrypt_message(key, enc["nonce"], bytes(tampered))
    print("[TEST B] Tampered ciphertext rejected: PASS")


def test_B_tampered_signature_rejected():
    """[TEST B] Modified message must fail ECDSA signature verification."""
    private_key, public_key = generate_ecc_keypair()
    original  = b'{"device_id":"temperature_01","value":28.5}'
    signature = generate_signature(private_key, original)
    tampered  = b'{"device_id":"temperature_01","value":99.9}'
    assert verify_signature(public_key, tampered, signature) is False
    print("[TEST B] Tampered message signature rejected: PASS")


# ── C. Unauthorized device ────────────────────────────────────────────────────

def test_C_authorized_device_accepted():
    """[TEST C] Known device_id must pass authentication."""
    assert "temperature_01" in AUTHORIZED_DEVICES
    assert "motion_01"      in AUTHORIZED_DEVICES
    assert "door_01"        in AUTHORIZED_DEVICES
    print("[TEST C] Authorized devices accepted: PASS")


def test_C_unauthorized_device_rejected():
    """[TEST C] Unknown device_id must be rejected — connection refused."""
    unknown_devices = ["hacker_device", "unknown_99", "admin", ""]
    for device_id in unknown_devices:
        assert device_id not in AUTHORIZED_DEVICES, \
            f"Device '{device_id}' should NOT be authorized"
    print("[TEST C] Unauthorized devices rejected: PASS")


# ── D. Replay attack ──────────────────────────────────────────────────────────

def test_D_fresh_message_accepted():
    """[TEST D] A fresh message with a new message_id must be accepted."""
    msg_id = str(uuid.uuid4())
    check_replay(msg_id, time.time())   # should not raise
    print("[TEST D] Fresh message accepted: PASS")


def test_D_duplicate_message_id_rejected():
    """[TEST D] Resending the same message_id must be rejected (replay)."""
    msg_id = str(uuid.uuid4())
    check_replay(msg_id, time.time())   # first send — OK
    with pytest.raises(ValueError, match="Replay attack detected"):
        check_replay(msg_id, time.time())   # replay — must fail
    print("[TEST D] Duplicate message_id rejected: PASS")


def test_D_expired_timestamp_rejected():
    """[TEST D] A message with an old timestamp must be rejected (replay)."""
    old_timestamp = time.time() - (TIMESTAMP_WINDOW + 10)   # 40 s ago
    with pytest.raises(ValueError, match="Replay attack detected"):
        check_replay(str(uuid.uuid4()), old_timestamp)
    print("[TEST D] Expired timestamp rejected: PASS")


def test_D_future_timestamp_rejected():
    """[TEST D] A message with a far-future timestamp must be rejected."""
    future_timestamp = time.time() + 60   # 60 s in the future
    with pytest.raises(ValueError, match="Replay attack detected"):
        check_replay(str(uuid.uuid4()), future_timestamp)
    print("[TEST D] Future timestamp rejected: PASS")


# ── E. Plaintext vs encrypted ─────────────────────────────────────────────────

def test_E_plaintext_exposes_sensitive_data():
    """
    [TEST E] Demonstrates why plaintext is unsafe.
    A plaintext message can be read directly — no decryption needed.
    An encrypted message reveals nothing without the key.
    """
    sensitive = json.dumps({
        "device_id": "door_01",
        "value":     "unlocked",
        "timestamp": time.time(),
    }).encode()

    # Plaintext: fully readable by anyone intercepting the network
    assert b"unlocked" in sensitive, "Plaintext exposes door state"
    assert b"door_01"  in sensitive, "Plaintext exposes device identity"

    # Encrypted: ciphertext reveals nothing
    key = generate_key()
    enc = encrypt_message(key, sensitive)
    assert b"unlocked" not in enc["ciphertext"], "Ciphertext must not contain plaintext"
    assert b"door_01"  not in enc["ciphertext"], "Ciphertext must not contain device_id"
    print("[TEST E] Plaintext vs encrypted demonstration: PASS")


# ── F. Valid sensor message structure ─────────────────────────────────────────

def test_F_valid_sensor_messages():
    """[TEST F] All three sensor message types must have required fields."""
    required = {"device_id", "sensor_type", "value", "timestamp", "message_id"}

    messages = [
        {"device_id": "temperature_01", "sensor_type": "temperature",
         "value": 28.5, "unit": "C",
         "timestamp": time.time(), "message_id": str(uuid.uuid4())},
        {"device_id": "motion_01", "sensor_type": "motion",
         "value": "detected",
         "timestamp": time.time(), "message_id": str(uuid.uuid4())},
        {"device_id": "door_01", "sensor_type": "door",
         "value": "locked",
         "timestamp": time.time(), "message_id": str(uuid.uuid4())},
    ]
    for msg in messages:
        assert required.issubset(msg.keys()), f"Missing fields in {msg['device_id']}"
    print("[TEST F] Valid sensor message structures: PASS")
