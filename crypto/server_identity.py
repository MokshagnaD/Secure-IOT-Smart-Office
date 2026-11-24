"""
crypto/server_identity.py
Persistent server ECC identity key management.

The server uses this key pair to:
  - Sign responses sent to clients (non-repudiation).
  - Participate in ECDH session-key exchange.

The key is generated once and stored in device_keys/server.priv.pem.
On every restart the same key is loaded, so clients can pin the server's
public key if needed.
"""

import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

BASE_DIR  = Path(__file__).resolve().parent.parent
KEYS_DIR  = BASE_DIR / "device_keys"
KEYS_DIR.mkdir(exist_ok=True)
_KEY_PATH = KEYS_DIR / "server.priv.pem"


def load_or_create_server_keypair():
    """
    Load the server's persistent ECC private key from disk.
    If it does not exist yet, generate and save it (first run only).

    Returns (private_key, public_key).
    """
    if _KEY_PATH.exists():
        private_key = load_pem_private_key(_KEY_PATH.read_bytes(), password=None)
    else:
        private_key = generate_private_key(SECP256R1())
        pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        _KEY_PATH.write_bytes(pem)
        os.chmod(_KEY_PATH, 0o600)
        print(f"[SERVER] Generated new server identity key: {_KEY_PATH}")

    return private_key, private_key.public_key()
