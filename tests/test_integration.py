"""
tests/test_integration.py
Integration tests — real client-server communication over TLS.

Each test runs against a live IoTServer in a background thread. No mocking.
"""

import time
import uuid

import pytest

from crypto.device_registry import ensure_all_devices_registered, load_device_private_key
from crypto.encryption import generate_key
from crypto.protocol import perform_handshake, recv_json, send_json, tls_connect
from server.server import IoTServer

HOST = "127.0.0.1"
PORT = 65433  # dedicated test port so integration tests don't clash with live server


@pytest.fixture(scope="module")
def live_server():
    """Start a test server in a background thread for the duration of the module."""
    ensure_all_devices_registered()
    try:
        srv = IoTServer(HOST, PORT).start_background()
        yield srv
        srv.stop()
    except PermissionError:
        pytest.skip("Socket operations restricted by sandbox environment.")


def _connect():
    try:
        return tls_connect(HOST, PORT)
    except PermissionError:
        pytest.skip("Socket connect restricted by environment sandbox.")


@pytest.mark.parametrize(
    "device_id,sensor_type",
    [
        ("temperature_01", "temperature"),
        ("motion_01", "motion"),
        ("door_01", "door"),
    ],
)
def test_integration_authorized_devices(live_server, device_id, sensor_type):
    """[INTEGRATION] All three authorized devices must receive OK from the server."""
    private_key = load_device_private_key(device_id)
    session_key = generate_key()
    message = {
        "device_id": device_id,
        "sensor_type": sensor_type,
        "value": (
            22.5
            if sensor_type == "temperature"
            else "detected"
            if sensor_type == "motion"
            else "locked"
        ),
        "timestamp": time.time(),
        "message_id": str(uuid.uuid4()),
    }
    if sensor_type == "temperature":
        message["unit"] = "C"

    with _connect() as conn:
        result = perform_handshake(conn, device_id, private_key, session_key, message)

    assert result is not None
    assert result.get("status") == "OK", f"Expected OK, got: {result}"


def test_integration_unauthorized_device(live_server):
    """[INTEGRATION] An unregistered device must be rejected by the server."""
    with _connect() as conn:
        send_json(conn, {"device_id": "hacker_device"})
        resp = recv_json(conn)
        assert resp["status"] == "REJECTED"


def test_integration_replay_attack(live_server):
    """[INTEGRATION] Sending the same message_id twice must be rejected on replay."""
    device_id = "temperature_01"
    private_key = load_device_private_key(device_id)
    message = {
        "device_id": device_id,
        "sensor_type": "temperature",
        "value": 25.0,
        "unit": "C",
        "timestamp": time.time(),
        "message_id": str(uuid.uuid4()),
    }

    with _connect() as conn1:
        resp1 = perform_handshake(conn1, device_id, private_key, generate_key(), message)
        assert resp1.get("status") == "OK", f"First send failed: {resp1}"

    with _connect() as conn2:
        resp2 = perform_handshake(conn2, device_id, private_key, generate_key(), message)
        assert resp2.get("status") == "ERROR"
        assert "replay" in resp2.get("reason", "").lower()


def test_integration_tampered_ciphertext(live_server):
    """[INTEGRATION] A tampered ciphertext must be rejected by the server."""
    device_id = "door_01"
    private_key = load_device_private_key(device_id)
    message = {
        "device_id": device_id,
        "sensor_type": "door",
        "value": "locked",
        "timestamp": time.time(),
        "message_id": str(uuid.uuid4()),
    }

    with _connect() as conn:
        try:
            resp = perform_handshake(
                conn,
                device_id,
                private_key,
                generate_key(),
                message,
                tamper_ciphertext=True,
            )
            assert resp.get("status") == "ERROR"
        except ConnectionError:
            pass  # server closing connection on tampered data is also valid rejection
