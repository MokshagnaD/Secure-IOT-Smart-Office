"""
server/server.py
Secure IoT Smart Office Server with Role-Based Access Control (RBAC).

Features:
- Dual-layer security: TLS 1.3 transport + AES-256-GCM application encryption.
- Hardware/Device identity: ECDSA digital signatures using trusted pre-registered keys.
- Key agreement: Ephemeral ECDH (P-256) session key exchange with HKDF-SHA256.
- Role-Based Access Control (RBAC): Policy Enforcement Point (PEP) evaluates access
  requests for ADMIN, EMPLOYEE, and GUEST roles on office resources.
- Replay attack mitigation via timestamp validity windows and UUID deduplication.
"""

import base64
import json
import logging
import socket
import ssl
import sys
import threading
import time
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization

from crypto.db import update_office_state
from crypto.device_registry import (
    AUTHORIZED_DEVICE_IDS,
    ensure_all_devices_registered,
    is_registered,
    load_device_public_key,
)
from crypto.encryption import decrypt_message, encrypt_message
from crypto.key_management import unwrap_session_key
from crypto.protocol import recv_frame, send_frame
from crypto.rbac import evaluate_access_request
from crypto.server_identity import load_or_create_server_keypair
from crypto.signatures import generate_signature, verify_signature
from crypto.tls_setup import CERT_FILE, KEY_FILE, ensure_tls_certificates

# ── Configuration ─────────────────────────────────────────────────────────────

HOST = "127.0.0.1"
PORT = 65432
TIMESTAMP_WINDOW = 30  # seconds

# ── Logging ───────────────────────────────────────────────────────────────────

(BASE_DIR / "logs").mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(BASE_DIR / "logs" / "server.log", encoding="utf-8"),
    ],
)
log = logging.getLogger(__name__)


class IoTServer:
    def __init__(self, host: str = HOST, port: int = PORT):
        self.host = host
        self.port = port
        self._running = False
        self._raw_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._ready_event = threading.Event()

        # Load persistent server identity key (generated once, reused on restart)
        self.private_key, self.public_key = load_or_create_server_keypair()
        log.info("[SERVER] Server identity key loaded.")

        # Ensure all authorized devices have registered keys
        ensure_all_devices_registered()

        # Track seen message IDs in memory to detect replays within a session
        self._seen_ids: set = set()
        self._seen_ids_lock = threading.Lock()

        # In-memory Smart Office state
        self.office_state = {
            "door_server_room": "locked",
            "door_main_entrance": "locked",
            "hvac_office": {"temperature": 22.5, "setpoint": 22.0, "mode": "AUTO"},
            "motion_meeting_room": "clear",
            # Legacy backward-compatibility mappings
            "door_01": "locked",
            "temperature_01": 22.5,
            "motion_01": "clear",
        }

    # ── TLS context ───────────────────────────────────────────────────────────

    def _build_tls_context(self) -> ssl.SSLContext:
        """
        Build a TLS server context.
        Auto-provisions dev certificates if absent and falls back to TLS 1.2
        if the host OpenSSL lacks TLS 1.3 support.
        """
        ensure_tls_certificates(CERT_FILE, KEY_FILE)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        except (AttributeError, ValueError):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        return ctx

    # ── Replay protection ─────────────────────────────────────────────────────

    def _check_replay(self, message_id: str, timestamp: float) -> None:
        """
        Reject messages that are expired or already seen.
        Raises ValueError on rejection.
        """
        now = time.time()
        age = now - timestamp
        if age > TIMESTAMP_WINDOW or age < -5:
            raise ValueError(
                f"[SECURITY] Replay attack detected: timestamp expired "
                f"(age={age:.1f}s, window={TIMESTAMP_WINDOW}s). Message rejected."
            )
        with self._seen_ids_lock:
            if message_id in self._seen_ids:
                raise ValueError(
                    f"[SECURITY] Replay attack detected: duplicate message_id "
                    f"'{message_id}'. Message rejected."
                )
            self._seen_ids.add(message_id)

    # ── Per-connection handler ────────────────────────────────────────────────

    def _handle_client(self, conn: ssl.SSLSocket, addr):
        log.info(f"\n[TLS] Connection from {addr}")
        log.info(f"[TLS] Protocol : {conn.version()}")
        log.info(f"[TLS] Cipher   : {conn.cipher()}")

        try:
            # ── Step 1: Receive device hello ──────────────────────────────────
            raw = self._recv_msg(conn)
            hello = json.loads(raw)
            device_id = hello.get("device_id", "")

            # ── Step 2: Device authentication — whitelist check ───────────────
            if device_id not in AUTHORIZED_DEVICE_IDS or not is_registered(device_id):
                log.warning(f"[AUTH] Unauthorized device: '{device_id}'. Connection rejected.")
                self._send_msg(
                    conn,
                    json.dumps({"status": "REJECTED", "reason": "unauthorized"}).encode(),
                )
                return
            log.info(f"[AUTH] Device ID recognized: {device_id}")

            # ── Step 3: Load the TRUSTED public key from the server registry ──
            trusted_public_key = load_device_public_key(device_id)
            log.info(f"[AUTH] Trusted public key loaded from registry for: {device_id}")

            # ── Step 4: Send server public key for session-key exchange ───────
            pub_bytes = self.public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            self._send_msg(
                conn, json.dumps({"server_public_key": pub_bytes.decode()}).encode()
            )

            # ── Step 5: Receive wrapped session key ───────────────────────────
            raw = self._recv_msg(conn)
            wrapped_payload = json.loads(raw)
            wrapped = {
                "ephemeral_public_key": wrapped_payload["ephemeral_public_key"].encode(),
                "nonce": base64.b64decode(wrapped_payload["nonce"]),
                "ciphertext": base64.b64decode(wrapped_payload["ciphertext"]),
            }
            session_key = unwrap_session_key(wrapped, self.private_key)
            log.info("[CRYPTO] Session key established via ECDH key exchange.")

            # ── Step 6: Receive encrypted sensor message ──────────────────────
            raw = self._recv_msg(conn)
            envelope = json.loads(raw)
            log.info("[SERVER] Encrypted message received.")

            nonce = base64.b64decode(envelope["nonce"])
            ciphertext = base64.b64decode(envelope["ciphertext"])
            aad = envelope.get("aad", "").encode()
            signature = base64.b64decode(envelope["signature"])
            signed_data = base64.b64decode(envelope["signed_data"])

            # ── Step 7: Verify ECDSA signature using TRUSTED registry key ─────
            if not verify_signature(trusted_public_key, signed_data, signature):
                raise ValueError(
                    f"[SECURITY] Signature verification FAILED for '{device_id}'. "
                    "Message rejected."
                )
            log.info(f"[AUTH] Device authenticated: {device_id}")
            log.info("[CRYPTO] Digital signature verified: SUCCESS")

            # ── Step 8: Decrypt application payload ───────────────────────────
            plaintext = decrypt_message(session_key, nonce, ciphertext, aad)
            log.info("[CRYPTO] AES-256-GCM decryption: SUCCESS")

            # ── Step 9: Parse and validate JSON ───────────────────────────────
            data = json.loads(plaintext)
            if not isinstance(data, dict):
                raise ValueError("Payload must be a JSON object.")

            if "device_id" not in data or "timestamp" not in data or "message_id" not in data:
                raise ValueError("Invalid message structure: missing metadata.")

            if data["device_id"] != device_id:
                raise ValueError(
                    f"[SECURITY] device_id mismatch: claimed '{device_id}', "
                    f"payload says '{data['device_id']}'. Rejected."
                )

            # ── Step 10: Replay protection ────────────────────────────────────
            self._check_replay(data["message_id"], data["timestamp"])

            # ── Step 11: Process office request (RBAC or Telemetry) ───────────
            response_payload = self._process_message(data)

            # ── Step 12: Send encrypted + signed response ─────────────────────
            response = json.dumps(response_payload).encode()
            enc = encrypt_message(session_key, response)
            resp_sig = generate_signature(self.private_key, response)
            self._send_msg(
                conn,
                json.dumps(
                    {
                        "nonce": base64.b64encode(enc["nonce"]).decode(),
                        "ciphertext": base64.b64encode(enc["ciphertext"]).decode(),
                        "signature": base64.b64encode(resp_sig).decode(),
                        "signed_data": base64.b64encode(response).decode(),
                    }
                ).encode(),
            )
            log.info("[SERVER] Encrypted response sent.")

        except InvalidTag:
            msg = "[SECURITY] AES-256-GCM authentication tag FAILED: ciphertext or AAD was tampered."
            log.warning(msg)
            try:
                self._send_msg(
                    conn, json.dumps({"status": "ERROR", "reason": msg}).encode()
                )
            except Exception:
                pass
        except ValueError as e:
            log.warning(str(e))
            try:
                self._send_msg(
                    conn, json.dumps({"status": "ERROR", "reason": str(e)}).encode()
                )
            except Exception:
                pass
        except Exception as e:
            log.error(f"[SERVER] Unexpected error: {e}")
            try:
                self._send_msg(
                    conn,
                    json.dumps(
                        {"status": "ERROR", "reason": "Internal server error"}
                    ).encode(),
                )
            except Exception:
                pass
        finally:
            conn.close()

    def _process_message(self, data: dict) -> dict:
        """Process either an RBAC user access request/command or sensor telemetry."""
        # Case A: RBAC Access Request / Control Command
        if "action" in data and "user_id" in data:
            user_id = data["user_id"]
            action = data["action"]
            resource = data.get("resource", data["device_id"])
            claimed_role = data.get("role")

            decision = evaluate_access_request(user_id, action, resource, claimed_role)

            if decision["allowed"]:
                log.info(
                    f"[RBAC GRANTED] User '{user_id}' ({decision['role']}) -> "
                    f"ACTION: '{action}' ON '{resource}'. Authorization SUCCESS."
                )
                if action == "unlock":
                    self.office_state[resource] = "unlocked"
                    update_office_state(resource, "unlocked")
                elif action == "lock":
                    self.office_state[resource] = "locked"
                    update_office_state(resource, "locked")
                elif action == "configure" and "setpoint" in data:
                    setpoint = float(data["setpoint"])
                    if isinstance(self.office_state.get(resource), dict):
                        self.office_state[resource]["setpoint"] = setpoint
                    update_office_state(resource, {"setpoint": setpoint})

                return {
                    "status": "OK",
                    "rbac": "GRANTED",
                    "device_id": data["device_id"],
                    "user_id": user_id,
                    "role": decision["role"],
                    "action": action,
                    "resource": resource,
                    "message": f"Action '{action}' on '{resource}' authorized and executed.",
                    "office_state": self.office_state.get(resource),
                    "server_ts": time.time(),
                }

            log.warning(
                f"[RBAC DENIED] 403 Forbidden: User '{user_id}' ({decision['role']}) -> "
                f"ACTION: '{action}' ON '{resource}'. Reason: {decision['reason']}"
            )
            return {
                "status": "REJECTED",
                "error_code": decision.get("error_code", "RBAC_PERMISSION_DENIED"),
                "rbac": "DENIED",
                "device_id": data["device_id"],
                "user_id": user_id,
                "role": decision["role"],
                "action": action,
                "resource": resource,
                "reason": decision["reason"],
                "server_ts": time.time(),
            }

        # Case B: IoT Sensor Telemetry Report
        sensor_type = data.get("sensor_type")
        value = data.get("value")
        if sensor_type is not None and value is not None:
            self._process_sensor(data)
            return {
                "status": "OK",
                "device_id": data["device_id"],
                "message": "Sensor telemetry received and logged.",
                "server_ts": time.time(),
            }

        raise ValueError("Invalid message: Neither an RBAC action nor valid sensor telemetry.")

    def _process_sensor(self, data: dict):
        sensor = data.get("sensor_type", "unknown")
        value = data.get("value", "")
        unit = data.get("unit", "")
        device = data.get("device_id", "unknown")

        if device == "hvac_office" or sensor in ("temperature", "hvac"):
            log.info(f"[OFFICE SENSOR] Climate reading from {device}: {value} {unit}")
            if isinstance(self.office_state.get("hvac_office"), dict):
                self.office_state["hvac_office"]["temperature"] = value
            update_office_state("hvac_office", {"temperature": value})
        elif device == "motion_meeting_room" or sensor == "motion":
            log.info(f"[OFFICE SENSOR] Meeting room occupancy ({device}): {value}")
            self.office_state["motion_meeting_room"] = value
            update_office_state("motion_meeting_room", value)
        elif "door" in device or sensor == "door":
            log.info(f"[OFFICE SENSOR] Door status ({device}): {value}")
            self.office_state[device] = value
            update_office_state(device, value)
        else:
            log.info(f"[OFFICE SENSOR] Sensor data from {device}: {value}")

    # ── Framing helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _send_msg(conn, data: bytes):
        send_frame(conn, data)

    @staticmethod
    def _recv_msg(conn) -> bytes:
        return recv_frame(conn)

    # ── Lifecycle & main loop ─────────────────────────────────────────────────

    def start(self):
        """Start the TLS socket server and block until stopped."""
        tls_ctx = self._build_tls_context()
        self._raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                self._raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        self._raw_sock.bind((self.host, self.port))
        self._raw_sock.listen(5)
        self._raw_sock.settimeout(0.5)
        self._running = True
        self._ready_event.set()

        log.info(f"[SERVER] Listening on {self.host}:{self.port}")
        log.info("[TLS] TLS context ready. Waiting for connections...")

        try:
            while self._running:
                try:
                    raw_conn, addr = self._raw_sock.accept()
                    try:
                        tls_conn = tls_ctx.wrap_socket(raw_conn, server_side=True)
                        threading.Thread(
                            target=self._handle_client,
                            args=(tls_conn, addr),
                            daemon=True,
                        ).start()
                    except ssl.SSLError as e:
                        log.warning(f"[TLS] Handshake failed from {addr}: {e}")
                        raw_conn.close()
                except socket.timeout:
                    continue
                except (KeyboardInterrupt, SystemExit):
                    log.info("[SERVER] Shutting down...")
                    break
                except OSError:
                    break
        finally:
            self.stop()

    def start_background(self, timeout: float = 4.0) -> "IoTServer":
        """Launch the server in a daemon thread and wait until its socket is listening."""
        self._ready_event.clear()
        self._thread = threading.Thread(target=self.start, daemon=True)
        self._thread.start()
        self._ready_event.wait(timeout=timeout)
        return self

    def stop(self):
        """Gracefully stop the server and close the listening socket."""
        self._running = False
        if self._raw_sock is not None:
            try:
                self._raw_sock.close()
            except Exception:
                pass
            self._raw_sock = None


if __name__ == "__main__":
    IoTServer().start()
