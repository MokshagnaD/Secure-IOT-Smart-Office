"""
crypto/device_registry.py
Trusted device registry — maps device_id to its registered ECC public key.

Security model
──────────────
The server NEVER trusts a public key sent by a connecting client.
Instead, each device's public key is registered in advance (out-of-band)
and stored on the server in the `device_keys/` directory.

At connection time the server:
  1. Looks up the device_id in the registry.
  2. Loads the pre-registered public key from disk.
  3. Verifies the ECDSA signature using ONLY that trusted key.

This prevents a rogue device from impersonating a legitimate device by
sending a forged device_id with its own public key.

Device registration (run once per device, before deployment):
  python -m crypto.device_registry register <device_id>
  → generates a key pair, saves the private key for the device,
    and registers the public key on the server side.
"""

import sys
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key

BASE_DIR     = Path(__file__).resolve().parent.parent
KEYS_DIR     = BASE_DIR / "device_keys"
KEYS_DIR.mkdir(exist_ok=True)

# Authorized device IDs — Smart Office IoT devices + legacy demo devices
AUTHORIZED_DEVICE_IDS = {
    # Smart Office devices
    "door_server_room",       # Restricted Server Room Access Lock
    "door_main_entrance",     # Main Office Entrance Access Lock
    "hvac_office",            # Office Climate & Temperature Controller
    "motion_meeting_room",    # Meeting Room Occupancy Sensor
    # Legacy devices (retained for backward compatibility)
    "temperature_01",
    "motion_01",
    "door_01",
}


def _pub_key_path(device_id: str) -> Path:
    return KEYS_DIR / f"{device_id}.pub.pem"


def _priv_key_path(device_id: str) -> Path:
    return KEYS_DIR / f"{device_id}.priv.pem"


def register_device(device_id: str) -> None:
    """
    Generate and persist an ECC key pair for a device.

    - Private key → device_keys/<device_id>.priv.pem  (device keeps this)
    - Public key  → device_keys/<device_id>.pub.pem   (server trusts this)

    In a real deployment the private key would be provisioned onto the
    physical device and never leave it. Here both files live locally for
    simulation purposes.
    """
    if device_id not in AUTHORIZED_DEVICE_IDS:
        raise ValueError(f"Device '{device_id}' is not in the authorized device list.")

    private_key = generate_private_key(SECP256R1())
    public_key  = private_key.public_key()

    # Save private key (no password for simplicity in this demo)
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    priv_path = _priv_key_path(device_id)
    priv_path.write_bytes(priv_pem)
    os.chmod(priv_path, 0o600)   # owner read/write only

    # Save public key
    pub_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _pub_key_path(device_id).write_bytes(pub_pem)

    print(f"[REGISTRY] Registered device '{device_id}'")
    print(f"           Private key : {priv_path}")
    print(f"           Public key  : {_pub_key_path(device_id)}")


def load_device_private_key(device_id: str):
    """Load the device's private key from disk (used by the simulated client)."""
    path = _priv_key_path(device_id)
    if not path.exists():
        raise FileNotFoundError(
            f"Private key for '{device_id}' not found. "
            f"Run: python -m crypto.device_registry register {device_id}"
        )
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(path.read_bytes(), password=None)


def load_device_public_key(device_id: str):
    """
    Load the server-trusted public key for a device.
    Called by the SERVER to verify signatures — never trusts client-supplied keys.
    """
    path = _pub_key_path(device_id)
    if not path.exists():
        raise FileNotFoundError(
            f"No registered public key for device '{device_id}'. "
            "Device must be registered before connecting."
        )
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    return load_pem_public_key(path.read_bytes())


def is_registered(device_id: str) -> bool:
    """Return True if the device has a registered public key on the server."""
    return _pub_key_path(device_id).exists()


def ensure_all_devices_registered() -> None:
    """Register all authorized devices that don't yet have keys (idempotent)."""
    for device_id in AUTHORIZED_DEVICE_IDS:
        if not is_registered(device_id):
            register_device(device_id)
            print(f"[REGISTRY] Auto-registered '{device_id}'")
        else:
            print(f"[REGISTRY] '{device_id}' already registered.")


# ── CLI: python -m crypto.device_registry register <device_id> ───────────────
if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "register":
        register_device(sys.argv[2])
    elif len(sys.argv) == 2 and sys.argv[1] == "register-all":
        ensure_all_devices_registered()
    else:
        print("Usage:")
        print("  python -m crypto.device_registry register <device_id>")
        print("  python -m crypto.device_registry register-all")
        print(f"\nAuthorized device IDs: {sorted(AUTHORIZED_DEVICE_IDS)}")
