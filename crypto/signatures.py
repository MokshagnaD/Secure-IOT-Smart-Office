"""
crypto/signatures.py
ECDSA digital signatures with SHA-256.

Why digital signatures?
────────────────────────
- Authentication  : only the holder of the private key can produce a valid
                    signature, proving the message came from a known device.
- Integrity       : any modification to the message invalidates the signature.
- Non-repudiation : the signer cannot later deny having signed the message
                    because only they hold the private key.

Algorithm: ECDSA with SHA-256 on SECP256R1.
- SHA-256 hashes the message before signing (handles arbitrary message size).
- ECDSA produces a compact signature (~64–72 bytes) suitable for IoT.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def generate_signature(private_key, message: bytes) -> bytes:
    """
    Sign a message with an ECC private key using ECDSA + SHA-256.

    Returns the DER-encoded signature bytes.
    The message is hashed with SHA-256 internally by the library.
    """
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    """
    Verify an ECDSA signature.

    Returns True  if the signature is valid for this message and public key.
    Returns False if the message was modified or the signature is invalid.

    This demonstrates:
    - Valid message   → verification SUCCESS
    - Modified message → verification FAILED  (integrity protection)
    """
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
