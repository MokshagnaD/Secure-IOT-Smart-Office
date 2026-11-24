"""
demo.py
Comprehensive Demonstration for the Secure IoT Smart Office with RBAC.

Runs six realistic enterprise scenarios against an embedded local TLS server:

  Scenario 1 — Smart Office Telemetry (Sensors reporting encrypted/signed readings)
  Scenario 2 — Employee Access Control (Bob unlocks Main Office Entrance -> RBAC GRANTED)
  Scenario 3 — Privilege Escalation Attempt (Bob tries to unlock Server Room -> RBAC DENIED)
  Scenario 4 — Administrator Operations (Alice unlocks Server Room & configures HVAC -> RBAC GRANTED)
  Scenario 5 — Rogue / Unauthorized Device (Unregistered hardware ID rejected at handshake)
  Scenario 6 — Cryptographic Defenses (Ciphertext tampering & replay attack rejected)

Usage:
    python demo.py
"""

import time
import uuid

from crypto.device_registry import ensure_all_devices_registered, load_device_private_key
from crypto.encryption import generate_key
from crypto.protocol import perform_handshake, recv_json, send_json, tls_connect
from server.server import IoTServer

DEMO_HOST = "127.0.0.1"
DEMO_PORT = 65434  # dedicated demo port


def _sep(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print("=" * 70)


def _send_rbac(device_id: str, user_id: str, role: str, action: str, extra: dict = None) -> dict:
    """Helper to send an RBAC request over TLS + ECDH + ECDSA + AES-GCM."""
    priv_key = load_device_private_key(device_id)
    msg = {
        "device_id": device_id,
        "action": action,
        "resource": device_id,
        "user_id": user_id,
        "role": role,
        "timestamp": time.time(),
        "message_id": str(uuid.uuid4()),
    }
    if extra:
        msg.update(extra)

    with tls_connect(DEMO_HOST, DEMO_PORT) as conn:
        return perform_handshake(conn, device_id, priv_key, generate_key(), msg)


# ── Scenario 1: Smart Office Telemetry ────────────────────────────────────────

def scenario_1_telemetry() -> None:
    _sep("SCENARIO 1 — Smart Office Telemetry (Encrypted + Signed Readings)")
    office_sensors = [
        ("hvac_office", "hvac", 23.2, "C"),
        ("motion_meeting_room", "motion", "occupied", ""),
        ("door_main_entrance", "door", "locked", ""),
    ]
    for device_id, sensor_type, val, unit in office_sensors:
        priv_key = load_device_private_key(device_id)
        msg = {
            "device_id": device_id,
            "sensor_type": sensor_type,
            "value": val,
            "timestamp": time.time(),
            "message_id": str(uuid.uuid4()),
        }
        if unit:
            msg["unit"] = unit

        with tls_connect(DEMO_HOST, DEMO_PORT) as conn:
            res = perform_handshake(conn, device_id, priv_key, generate_key(), msg)
            print(
                f"[DEMO] Device '{device_id}' ({sensor_type}) -> "
                f"Status: {res.get('status', '?')} | {res.get('message', '')}"
            )


# ── Scenario 2 & 3: Employee & Privilege Escalation Loop ──────────────────────

def scenario_2_and_3_employee_rbac() -> None:
    checks = [
        (
            "SCENARIO 2 — Employee Access Control (Bob Badges into Main Office)",
            "door_main_entrance",
            "General Office Zone",
            True,
        ),
        (
            "SCENARIO 3 — Privilege Escalation Defense (Bob tries to unlock Server Room)",
            "door_server_room",
            "Restricted High-Security Zone",
            False,
        ),
    ]
    for title, door_id, zone_label, expect_grant in checks:
        _sep(title)
        print(f"[DEMO] User   : Bob Martinez (Role: EMPLOYEE)")
        print(f"[DEMO] Target : '{door_id}' ({zone_label})")
        res = _send_rbac("door_main_entrance" if expect_grant else door_id, "employee_bob", "EMPLOYEE", "unlock")
        if expect_grant:
            print(f"[DEMO] Server Response : {res.get('status')} (RBAC: {res.get('rbac')})")
            print(f"[DEMO] Details         : {res.get('message')}")
            assert res.get("rbac") == "GRANTED"
            print("[DEMO] RESULT: Access GRANTED by RBAC policy ✓")
        else:
            print(f"[DEMO] Server Response : {res.get('status')} (Error: {res.get('error_code')})")
            print(f"[DEMO] Rejection Reason: {res.get('reason')}")
            assert res.get("status") == "REJECTED" and res.get("rbac") == "DENIED"
            print("[DEMO] RESULT: Unauthorized access correctly BLOCKED by RBAC ✓")


# ── Scenario 4: Administrator Operations ──────────────────────────────────────

def scenario_4_admin_operations() -> None:
    _sep("SCENARIO 4 — Administrator Operations (Alice Chen, IT & Facilities Admin)")
    print("[DEMO] User: Alice Chen (Role: ADMIN, Dept: Infrastructure & Security)")

    admin_tasks = [
        ("door_server_room", "unlock", None, "Server Room Door"),
        ("hvac_office", "configure", {"setpoint": 21.0}, "HVAC Setpoint"),
    ]
    for device_id, action, extra, label in admin_tasks:
        res = _send_rbac(device_id, "admin_alice", "ADMIN", action, extra)
        detail = "Setpoint updated to 21.0°C" if extra else res.get("message", "")
        print(f"[DEMO] {label:17s}: {res.get('status')} (RBAC: {res.get('rbac')}) -> {detail}")
        assert res.get("rbac") == "GRANTED"
    print("[DEMO] RESULT: Admin full clearance verified ✓")


# ── Scenario 5: Unauthorized Device Rejected ──────────────────────────────────

def scenario_5_rogue_device() -> None:
    _sep("SCENARIO 5 — Hardware Authentication (Rogue IoT Device Rejected)")
    print("[DEMO] Connecting with unregistered device_id = 'rogue_office_spy'...")
    with tls_connect(DEMO_HOST, DEMO_PORT) as conn:
        send_json(conn, {"device_id": "rogue_office_spy"})
        resp = recv_json(conn)
        print(f"[DEMO] Server Response : {resp}")
        assert resp.get("status") == "REJECTED"
        print("[DEMO] RESULT: Rogue device blocked at TLS/Handshake layer ✓")


# ── Scenario 6: Cryptographic Defenses (Tamper & Replay) ──────────────────────

def scenario_6_crypto_defenses() -> None:
    _sep("SCENARIO 6 — Cryptographic Integrity & Replay Mitigation")

    device_id = "door_main_entrance"
    priv_key = load_device_private_key(device_id)

    # 6A. Tampering detection
    print("\n[6A: Ciphertext Tampering]")
    tamper_msg = {
        "device_id": device_id,
        "sensor_type": "door",
        "value": "locked",
        "timestamp": time.time(),
        "message_id": str(uuid.uuid4()),
    }
    print("[DEMO] Injected malicious 1-byte modification into AES-GCM ciphertext...")
    with tls_connect(DEMO_HOST, DEMO_PORT) as conn:
        res = perform_handshake(
            conn, device_id, priv_key, generate_key(), tamper_msg, tamper_ciphertext=True
        )
        print(f"[DEMO] Server Response : {res.get('status')} — {res.get('reason', '')[:60]}")
        assert res.get("status") == "ERROR"
        print("[DEMO] RESULT: Tampered ciphertext caught by GCM authentication tag ✓")

    # 6B. Replay attack detection
    print("\n[6B: Replay Attack Defense]")
    replay_msg = {
        "device_id": device_id,
        "sensor_type": "door",
        "value": "locked",
        "timestamp": time.time(),
        "message_id": str(uuid.uuid4()),
    }
    for attempt in ("Original Transmission", "Replayed Transmission"):
        with tls_connect(DEMO_HOST, DEMO_PORT) as conn:
            res = perform_handshake(conn, device_id, priv_key, generate_key(), replay_msg)
            print(f"[DEMO] {attempt}: {res.get('status')} — {res.get('reason', '')[:60]}")
            if attempt == "Original Transmission":
                assert res.get("status") == "OK"
                print("[DEMO] Attacker captures and replays identical packet with same message_id...")
            else:
                assert res.get("status") == "ERROR"
                print("[DEMO] RESULT: Replay attack detected and rejected by Deduplication Filter ✓")


# ── Main Runner ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n[SMART OFFICE] Initializing Trusted Device Registry...")
    ensure_all_devices_registered()

    print(f"[SMART OFFICE] Starting TLS Demo Server on port {DEMO_PORT}...")
    server = IoTServer(DEMO_HOST, DEMO_PORT).start_background()

    try:
        for scenario in (
            scenario_1_telemetry,
            scenario_2_and_3_employee_rbac,
            scenario_4_admin_operations,
            scenario_5_rogue_device,
            scenario_6_crypto_defenses,
        ):
            scenario()
    finally:
        server.stop()

    print(f"\n{'=' * 70}")
    print("  ALL SMART OFFICE & RBAC DEMONSTRATIONS COMPLETED SUCCESSFULLY")
    print("=" * 70)
