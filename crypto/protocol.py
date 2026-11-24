"""
crypto/protocol.py
Shared TLS transport, length-prefixed framing, and cryptographic handshake helpers.

Used consistently across `client/iot_client.py`, `dashboard.py`, `demo.py`,
and `tests/test_integration.py` so wire-protocol logic lives in one place.
"""

import base64
import json
import socket
import ssl
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from crypto.encryption import decrypt_message, encrypt_message
from crypto.key_management import wrap_session_key
from crypto.signatures import generate_signature, verify_signature
from crypto.tls_setup import CERT_FILE, ensure_tls_certificates

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 65432


def send_frame(conn, data: bytes) -> None:
    """Send a 4-byte big-endian length-prefixed message."""
    conn.sendall(len(data).to_bytes(4, "big") + data)


def recvall(conn, n: int) -> bytes:
    """Receive exactly n bytes from a socket or raise ConnectionError."""
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly.")
        buf += chunk
    return buf


def recv_frame(conn) -> bytes:
    """Receive a 4-byte big-endian length-prefixed message."""
    raw_len = recvall(conn, 4)
    return recvall(conn, int.from_bytes(raw_len, "big"))


def send_json(conn, payload: Dict[str, Any]) -> None:
    """Serialize dict as JSON and send as a framed message."""
    send_frame(conn, json.dumps(payload).encode())


def recv_json(conn) -> Dict[str, Any]:
    """Receive a framed JSON message and return a dict."""
    return json.loads(recv_frame(conn))


def build_client_tls_context(ca_cert: Path = CERT_FILE) -> ssl.SSLContext:
    """
    Build a TLS 1.3 (fallback TLS 1.2) client SSLContext verifying server cert.
    Auto-provisions the local dev certificate if missing.
    """
    if ca_cert == CERT_FILE and not ca_cert.exists():
        ensure_tls_certificates()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    except (AttributeError, ValueError):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=ca_cert)
    return ctx


def tls_connect(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    ca_cert: Path = CERT_FILE,
    timeout: float = 5.0,
) -> ssl.SSLSocket:
    """Open a verified TLS connection to the IoT Security Gateway."""
    ctx = build_client_tls_context(ca_cert)
    raw = socket.create_connection((host, port), timeout=timeout)
    return ctx.wrap_socket(raw, server_hostname="localhost")


def perform_handshake(
    conn: ssl.SSLSocket,
    device_id: str,
    private_key,
    session_key: bytes,
    message: dict,
    *,
    tamper_ciphertext: bool = False,
    verify_server_sig: bool = True,
) -> Dict[str, Any]:
    """
    Execute the complete multi-layer client protocol handshake:
      1. Device ID authentication hello
      2. Receive server ECC public key
      3. Wrap session key via ECDH + HKDF-SHA256
      4. Sign plaintext with ECDSA & encrypt with AES-256-GCM
      5. Receive, optionally verify signature, and decrypt server response
    """
    # Step 1: Device hello
    send_json(conn, {"device_id": device_id})
    resp = recv_json(conn)
    if resp.get("status") == "REJECTED":
        return resp

    # Step 2 & 3: Server public key & session key exchange
    server_pub = load_pem_public_key(resp["server_public_key"].encode())
    wrapped = wrap_session_key(session_key, server_pub)
    send_json(
        conn,
        {
            "ephemeral_public_key": wrapped["ephemeral_public_key"].decode(),
            "nonce": base64.b64encode(wrapped["nonce"]).decode(),
            "ciphertext": base64.b64encode(wrapped["ciphertext"]).decode(),
        },
    )

    # Step 4: Sign & encrypt application payload
    plaintext = json.dumps(message).encode()
    aad = device_id.encode()
    signature = generate_signature(private_key, plaintext)
    enc = encrypt_message(session_key, plaintext, aad)

    ciphertext_bytes = bytearray(enc["ciphertext"])
    if tamper_ciphertext:
        ciphertext_bytes[0] ^= 0xFF

    send_json(
        conn,
        {
            "nonce": base64.b64encode(enc["nonce"]).decode(),
            "ciphertext": base64.b64encode(bytes(ciphertext_bytes)).decode(),
            "aad": aad.decode(),
            "signature": base64.b64encode(signature).decode(),
            "signed_data": base64.b64encode(plaintext).decode(),
        },
    )

    # Step 5: Receive & decrypt response
    env = recv_json(conn)
    if env.get("status") in ("ERROR", "REJECTED") and "ciphertext" not in env:
        return env

    if verify_server_sig and "signature" in env and "signed_data" in env:
        resp_sig = base64.b64decode(env["signature"])
        resp_signed = base64.b64decode(env["signed_data"])
        if not verify_signature(server_pub, resp_signed, resp_sig):
            raise ValueError("[SECURITY] Server response signature verification FAILED.")

    plain = decrypt_message(
        session_key,
        base64.b64decode(env["nonce"]),
        base64.b64decode(env["ciphertext"]),
    )
    return json.loads(plain)
