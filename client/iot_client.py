"""
client/iot_client.py
Secure IoT Smart Office Client.

Simulates enterprise Smart Office IoT devices:
  - door_main_entrance   (Main Office Entrance Access Lock)
  - door_server_room     (Restricted Server Room Access Lock)
  - hvac_office          (Office Climate & Temperature Controller)
  - motion_meeting_room  (Meeting Room Occupancy Sensor)
  - Legacy devices (temperature_01, motion_01, door_01)

Security flow per message:
  1. Connect to server over TLS 1.3.
  2. Send device_id for hardware identity authentication.
  3. Receive server ECC public key.
  4. Generate AES-256 session key; wrap with server ECC public key (ECDH).
  5. Send wrapped session key.
  6. Build payload (Telemetry or RBAC Command).
  7. Sign plaintext payload with device's registered ECDSA private key.
  8. Encrypt payload with AES-256-GCM (AAD = device_id).
  9. Send encrypted envelope.
  10. Receive and decrypt server response; verify server digital signature.
"""

import logging
import random
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from crypto.device_registry import ensure_all_devices_registered, load_device_private_key
from crypto.encryption import generate_key
from crypto.protocol import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    perform_handshake,
    tls_connect,
)
from crypto.tls_setup import CERT_FILE

# ── Configuration ─────────────────────────────────────────────────────────────

HOST = DEFAULT_HOST
PORT = DEFAULT_PORT
CA_CERT = CERT_FILE

# ── Logging ───────────────────────────────────────────────────────────────────

(BASE_DIR / "logs").mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(BASE_DIR / "logs" / "client.log", encoding="utf-8"),
    ],
)
log = logging.getLogger(__name__)


class IoTDevice:
    """Simulates a single registered IoT device."""

    def __init__(self, device_id: str, sensor_type: str):
        self.device_id = device_id
        self.sensor_type = sensor_type
        ensure_all_devices_registered()
        self.private_key = load_device_private_key(device_id)
        self.public_key = self.private_key.public_key()

    def _generate_payload(self) -> dict:
        if self.sensor_type in ("temperature", "hvac"):
            return {"value": round(random.uniform(20.0, 26.0), 1), "unit": "C"}
        if self.sensor_type == "motion":
            return {"value": random.choice(["occupied", "clear"])}
        if self.sensor_type == "door":
            return {"value": random.choice(["locked", "unlocked"])}
        return {"value": "unknown"}

    def build_message(self) -> dict:
        """Build a sensor message with timestamp and unique message_id."""
        msg = {
            "device_id": self.device_id,
            "sensor_type": self.sensor_type,
            "timestamp": time.time(),
            "message_id": str(uuid.uuid4()),
        }
        msg.update(self._generate_payload())
        return msg

    def send_access_command(
        self,
        user_id: str,
        action: str,
        resource: Optional[str] = None,
        role: Optional[str] = None,
        extra_params: Optional[dict] = None,
    ) -> Optional[dict]:
        """Send an RBAC-controlled access request or command from an office badge."""
        target_resource = resource or self.device_id
        message = {
            "device_id": self.device_id,
            "action": action,
            "resource": target_resource,
            "user_id": user_id,
            "timestamp": time.time(),
            "message_id": str(uuid.uuid4()),
        }
        if role:
            message["role"] = role
        if extra_params:
            message.update(extra_params)
        return self.send_sensor_data(raw_message=message)

    def send_sensor_data(self, raw_message: Optional[dict] = None) -> Optional[dict]:
        """
        Full secure send flow:
        authenticate -> key exchange -> sign -> encrypt -> send -> verify response.
        """
        log.info(f"\n[CLIENT] Device     : {self.device_id}")
        log.info(f"[CLIENT] Sensor type: {self.sensor_type}")

        message = raw_message if raw_message is not None else self.build_message()
        if "value" in message:
            unit = f" {message.get('unit', '')}".rstrip()
            log.info(f"[CLIENT] Reading    : {message['value']}{unit}")
        elif "action" in message:
            log.info(
                f"[CLIENT] RBAC Action: {message.get('user_id')} -> "
                f"{message['action']} on {message.get('resource', self.device_id)}"
            )

        log.info(f"[TLS] Connecting to {HOST}:{PORT} using TLS...")
        with tls_connect(HOST, PORT, CA_CERT) as conn:
            log.info(f"[TLS] Protocol : {conn.version()}")
            log.info(f"[TLS] Cipher   : {conn.cipher()}")

            session_key = generate_key()
            resp_data = perform_handshake(
                conn,
                self.device_id,
                self.private_key,
                session_key,
                message,
                verify_server_sig=True,
            )

            if resp_data.get("status") == "REJECTED" and "rbac" not in resp_data:
                log.warning(f"[AUTH] Server rejected device: {resp_data.get('reason')}")
                return None
            if resp_data.get("status") == "ERROR":
                log.warning(f"[SERVER] Error response: {resp_data.get('reason')}")
                return resp_data
            if resp_data.get("status") == "REJECTED":
                log.warning(
                    f"[CLIENT] Server REJECTED request: {resp_data.get('reason')} "
                    f"(Error: {resp_data.get('error_code')})"
                )
            else:
                log.info(
                    f"[CLIENT] Server response: {resp_data.get('status')} — "
                    f"{resp_data.get('message')}"
                )
            return resp_data


def run_all_devices():
    """Simulate Smart Office IoT devices sending telemetry in a loop."""
    office_devices = [
        ("door_main_entrance", "door"),
        ("door_server_room", "door"),
        ("hvac_office", "hvac"),
        ("motion_meeting_room", "motion"),
    ]
    for device_id, sensor_type in office_devices:
        IoTDevice(device_id, sensor_type).send_sensor_data()
        time.sleep(0.3)


if __name__ == "__main__":
    run_all_devices()
