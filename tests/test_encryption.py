"""
tests/test_encryption.py
Unit tests for AES-256-GCM encryption module.
"""

import pytest
from cryptography.exceptions import InvalidTag
from crypto.encryption import generate_key, encrypt_message, decrypt_message


def test_encrypt_decrypt_roundtrip():
    """[TEST] Normal encrypt → decrypt must return original plaintext."""
    key = generate_key()
    plaintext = b"temperature:28.5C"
    result = encrypt_message(key, plaintext)
    recovered = decrypt_message(key, result["nonce"], result["ciphertext"])
    assert recovered == plaintext, "Decrypted text must match original"
    print("\n[TEST] AES-256-GCM roundtrip: PASS")


def test_wrong_key_fails():
    """[TEST] Decryption with a different key must raise InvalidTag."""
    key1 = generate_key()
    key2 = generate_key()
    result = encrypt_message(key1, b"secret data")
    with pytest.raises(InvalidTag):
        decrypt_message(key2, result["nonce"], result["ciphertext"])
    print("[TEST] Wrong key rejection: PASS")


def test_modified_ciphertext_fails():
    """[TEST] Flipping a byte in the ciphertext must raise InvalidTag (integrity)."""
    key = generate_key()
    result = encrypt_message(key, b"sensor reading")
    tampered = bytearray(result["ciphertext"])
    tampered[0] ^= 0xFF                          # flip bits in first byte
    with pytest.raises(InvalidTag):
        decrypt_message(key, result["nonce"], bytes(tampered))
    print("[TEST] Modified ciphertext rejection: PASS")


def test_modified_aad_fails():
    """[TEST] Changing AAD after encryption must raise InvalidTag."""
    key = generate_key()
    aad = b"device_id:temperature_01"
    result = encrypt_message(key, b"28.5", aad)
    with pytest.raises(InvalidTag):
        decrypt_message(key, result["nonce"], result["ciphertext"], b"device_id:attacker")
    print("[TEST] Modified AAD rejection: PASS")


def test_unique_nonces():
    """[TEST] Two encryptions of the same plaintext must produce different nonces."""
    key = generate_key()
    r1 = encrypt_message(key, b"same data")
    r2 = encrypt_message(key, b"same data")
    assert r1["nonce"] != r2["nonce"], "Nonces must be unique per encryption"
    print("[TEST] Unique nonce generation: PASS")


def test_key_size():
    """[TEST] generate_key must return exactly 32 bytes (256 bits)."""
    key = generate_key()
    assert len(key) == 32
    print("[TEST] Key size 256-bit: PASS")
