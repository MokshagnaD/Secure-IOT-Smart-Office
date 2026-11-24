"""
crypto/key_management.py
ECC-based key management for secure session key establishment.

Why two layers of cryptography?
────────────────────────────────
- AES-256-GCM is used for actual sensor data because symmetric encryption
  is fast and efficient for bulk data.
- ECC (Elliptic Curve Cryptography) is used for key establishment because
  asymmetric cryptography lets two parties agree on a shared secret without
  ever transmitting the secret itself.

Key types:
- Private key : kept secret on the device/server, never transmitted.
- Public key  : shared openly; used by the other party to encrypt the
                session key or verify signatures.
- Session key : a fresh AES-256 key derived per session; encrypted with
                the recipient's ECC public key before transmission.

Algorithm choices:
- SECP256R1 (P-256): NIST-approved curve, widely supported, 128-bit
  security level — appropriate for an IoT context.
- ECIES-style wrapping: we use ECDH to derive a shared secret, then
  derive an AES key from it with HKDF-SHA256, and wrap the session key
  with that AES key.
"""

import os
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1, generate_private_key, ECDH
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from crypto.encryption import generate_key, encrypt_message, decrypt_message


def generate_ecc_keypair():
    """Generate an ECC private/public key pair on SECP256R1."""
    private_key = generate_private_key(SECP256R1())
    public_key  = private_key.public_key()
    return private_key, public_key


def _derive_wrapping_key(shared_secret: bytes) -> bytes:
    """Derive a 256-bit AES key from an ECDH shared secret using HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"iot-session-key-wrap",
    ).derive(shared_secret)


def wrap_session_key(session_key: bytes, recipient_public_key) -> dict:
    """
    Wrap (encrypt) a session key for a recipient using ECDH + AES-256-GCM.

    Steps:
    1. Generate an ephemeral ECC key pair.
    2. Perform ECDH with the recipient's public key → shared secret.
    3. Derive a wrapping key from the shared secret via HKDF-SHA256.
    4. Encrypt the session key with AES-256-GCM using the wrapping key.
    5. Send the ephemeral public key + encrypted session key to the recipient.

    The recipient can reproduce the shared secret using their private key
    and the ephemeral public key, then unwrap the session key.
    """
    ephemeral_private, ephemeral_public = generate_ecc_keypair()
    shared_secret  = ephemeral_private.exchange(ECDH(), recipient_public_key)
    wrapping_key   = _derive_wrapping_key(shared_secret)
    encrypted      = encrypt_message(wrapping_key, session_key)

    # Serialize ephemeral public key for transmission
    ephemeral_pub_bytes = ephemeral_public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "ephemeral_public_key": ephemeral_pub_bytes,
        "nonce":      encrypted["nonce"],
        "ciphertext": encrypted["ciphertext"],
    }


def unwrap_session_key(wrapped: dict, recipient_private_key) -> bytes:
    """
    Unwrap (decrypt) a session key using the recipient's ECC private key.

    Reverses wrap_session_key: reproduces the shared secret via ECDH,
    derives the wrapping key, and decrypts the session key.
    """
    ephemeral_public = serialization.load_pem_public_key(
        wrapped["ephemeral_public_key"]
    )
    shared_secret = recipient_private_key.exchange(ECDH(), ephemeral_public)
    wrapping_key  = _derive_wrapping_key(shared_secret)
    return decrypt_message(wrapping_key, wrapped["nonce"], wrapped["ciphertext"])
