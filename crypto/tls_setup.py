"""
crypto/tls_setup.py
Automatic self-signed ECDSA (P-256) TLS certificate provisioning for local dev.

Ensures `certificates/server.crt` and `certificates/server.key` exist so a fresh
repository clone runs out of the box without manual OpenSSL commands.
"""

import datetime
import ipaddress
import os
from pathlib import Path
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

BASE_DIR = Path(__file__).resolve().parent.parent
CERT_DIR = BASE_DIR / "certificates"
CERT_FILE = CERT_DIR / "server.crt"
KEY_FILE = CERT_DIR / "server.key"


def ensure_tls_certificates(
    cert_path: Path = CERT_FILE, key_path: Path = KEY_FILE
) -> Tuple[Path, Path]:
    """
    Create a self-signed P-256 TLS certificate/key pair if missing.
    Returns (cert_path, key_path).
    """
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(private_key, hashes.SHA256())
    )

    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[TLS] Generated self-signed certificate: {cert_path}")
    return cert_path, key_path
