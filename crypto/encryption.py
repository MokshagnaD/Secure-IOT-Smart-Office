"""
crypto/encryption.py
AES-256-GCM authenticated encryption.

Security decisions:
- AES-256: 256-bit key provides strong confidentiality.
- GCM mode: provides both encryption (confidentiality) AND authentication tag
  (integrity). A single primitive replaces separate HMAC.
- Nonce: 12-byte random nonce generated fresh for every encryption call.
  Reusing a nonce with the same key breaks GCM security completely.
- AAD (Additional Authenticated Data): binds the device_id to the ciphertext
  so an attacker cannot swap ciphertext between devices.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12   # 96-bit nonce — recommended for GCM
KEY_SIZE   = 32   # 256-bit key


def generate_key() -> bytes:
    """Return a cryptographically random 256-bit AES key."""
    return os.urandom(KEY_SIZE)


def encrypt_message(key: bytes, plaintext: bytes, aad: bytes = b"") -> dict:
    """
    Encrypt plaintext with AES-256-GCM.

    Returns a dict with:
        nonce      – random 12-byte value (safe to transmit in plaintext)
        ciphertext – encrypted bytes + 16-byte GCM authentication tag appended
        aad        – additional authenticated data (not encrypted, but authenticated)

    The GCM tag is automatically appended to ciphertext by the library.
    Decryption will raise InvalidTag if ciphertext or aad is modified.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes for AES-256")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad if aad else None)

    return {"nonce": nonce, "ciphertext": ciphertext, "aad": aad}


def decrypt_message(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """
    Decrypt and verify AES-256-GCM ciphertext.

    Raises cryptography.exceptions.InvalidTag if:
        - the key is wrong
        - the ciphertext was modified
        - the aad was modified
    This guarantees both confidentiality and integrity.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes for AES-256")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad if aad else None)
