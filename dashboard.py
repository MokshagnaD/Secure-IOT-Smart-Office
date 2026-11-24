"""
dashboard.py
Web dashboard for the Secure IoT Smart Office with Role-Based Access Control (RBAC).

Starts two services:
  - IoT Server   : port 65432  (TLS 1.3 encrypted socket server)
  - HTTP Server  : port 8080   (Interactive Web UI + REST API)

Usage:
    python dashboard.py
    Then open: http://localhost:8080
"""

import json
import logging
import os
import random
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

# Ensure unbuffered, real-time terminal output
os.environ["PYTHONUNBUFFERED"] = "1"
for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        try:
            stream.reconfigure(line_buffering=True)
        except Exception:
            pass


def tprint(*args, **kwargs) -> None:
    """Print directly to terminal and flush immediately."""
    print(*args, **kwargs)
    try:
        sys.stdout.flush()
    except Exception:
        pass


# ── Project imports ───────────────────────────────────────────────────────────
from crypto.db import (
    acknowledge_alert,
    acknowledge_all_alerts,
    authenticate_user,
    create_alert,
    get_alerts,
    get_all_office_telemetry,
    get_db,
    get_it_assets,
    get_office_state,
    get_recent_attendance,
    is_db_connected,
    log_attendance,
    record_blocked_attack,
    register_employee,
)
from crypto.device_registry import ensure_all_devices_registered, load_device_private_key
from crypto.encryption import generate_key
from crypto.key_management import generate_ecc_keypair
from crypto.protocol import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    perform_handshake,
    recv_json,
    send_json,
    tls_connect,
)
from crypto.rbac import USERS, get_rbac_stats, get_role_permissions
from crypto.tls_setup import ensure_tls_certificates
from server.server import IoTServer

BASE_DIR = Path(__file__).resolve().parent
IOT_PORT = DEFAULT_PORT
HTTP_PORT = 8080


# ── Log capture & recent activity feed ────────────────────────────────────────

class _LogCapture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records: List[str] = []

    def emit(self, record):
        msg = self.format(record)
        self.records.append(msg)
        # Print only if root logger lacks a StreamHandler to avoid duplicate terminal lines
        if not any(
            isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
            for h in logging.getLogger().handlers
        ):
            tprint(msg)

    def flush_records(self) -> List[str]:
        r, self.records = self.records, []
        return r


_log_capture = _LogCapture()
_log_capture.setFormatter(logging.Formatter("%(message)s"))
logging.getLogger().addHandler(_log_capture)
logging.getLogger().setLevel(logging.INFO)

_recent_events: List[Dict[str, Any]] = []


def _record_event(category: str, message: str, ok: bool = True) -> None:
    _recent_events.insert(
        0,
        {
            "time": time.strftime("%H:%M:%S"),
            "category": category,
            "message": message,
            "ok": ok,
        },
    )
    if len(_recent_events) > 25:
        _recent_events.pop()


_iot_server: Optional[IoTServer] = None


def _is_iot_running() -> bool:
    return _iot_server is not None and getattr(_iot_server, "_running", False)


def _make_message(device_id: str, sensor_type: str) -> dict:
    msg: Dict[str, Any] = {
        "device_id": device_id,
        "sensor_type": sensor_type,
        "timestamp": time.time(),
        "message_id": str(uuid.uuid4()),
    }
    if sensor_type in ("temperature", "hvac") or device_id == "hvac_office":
        setpoint = float(get_office_state()["hvac_office"].get("setpoint", 22.0))
        msg["value"] = round(setpoint + random.uniform(-0.6, 0.6), 1)
        msg["unit"] = "C"
    elif sensor_type == "motion" or device_id == "motion_meeting_room":
        msg["value"] = random.choice(["occupied", "clear"])
    elif sensor_type == "door" or "door" in device_id:
        msg["value"] = get_office_state().get(device_id, "locked")
    return msg


# ── API handlers ──────────────────────────────────────────────────────────────

def handle_server_start() -> dict:
    global _iot_server
    tprint("\n" + "=" * 70)
    tprint(" [WEB DASHBOARD] User clicked 'Start Server'")
    tprint("=" * 70)
    if _is_iot_running():
        tprint("[SERVER] IoT Gateway is already running.")
        return {"ok": True, "message": "already running", "logs": []}
    try:
        _iot_server = IoTServer(DEFAULT_HOST, IOT_PORT).start_background()
        tprint(
            f"[SERVER] IoT Gateway is ONLINE on port {IOT_PORT} "
            "(TLS 1.3 / AES-256-GCM / ECDSA)"
        )
        _record_event("GATEWAY", f"IoT TLS 1.3 Gateway started on port {IOT_PORT}", True)
        return {"ok": True, "logs": _log_capture.flush_records()}
    except Exception as e:
        tprint(f"[SERVER] Failed to start IoT Gateway: {e}")
        return {"ok": False, "error": str(e)}


def handle_server_stop() -> dict:
    global _iot_server
    tprint("\n" + "=" * 70)
    tprint(" [WEB DASHBOARD] User clicked 'Stop Server'")
    tprint("=" * 70)
    if _iot_server:
        _iot_server.stop()
        _iot_server = None
        tprint("[SERVER] IoT Gateway is now STOPPED.")
        _record_event("GATEWAY", "IoT TLS 1.3 Gateway stopped", False)
    return {"ok": True}


def handle_auth_login(email: str, password: str) -> dict:
    tprint("\n" + "-" * 70)
    tprint(f" [WEB AUTH] Sign-in attempt for email: '{email}'")
    res = authenticate_user(email, password)
    if res.get("ok"):
        u = res.get("user", {})
        tprint(
            f" [WEB AUTH] SUCCESS: {u.get('name')} | Role: {u.get('role')} | "
            f"Badge: {u.get('badge_id')}"
        )
        _record_event("AUTH", f"{u.get('name')} ({u.get('role')}) signed in", True)
    else:
        tprint(f" [WEB AUTH] FAILED: {res.get('error')}")
        _record_event("AUTH", f"Failed sign-in attempt for '{email}'", False)
    tprint("-" * 70)
    return res


def handle_auth_register(
    name: str, email: str, password: str, dept: str, badge_id: Optional[str]
) -> dict:
    tprint("\n" + "-" * 70)
    tprint(f" [WEB AUTH] Employee registration attempt: '{name}' <{email}> (Dept: {dept})")
    res = register_employee(
        name=name, email=email, password=password, department=dept, badge_id=badge_id
    )
    if res.get("ok"):
        u = res.get("user", {})
        tprint(
            f" [WEB AUTH] SUCCESS: Registered {u.get('name')} "
            f"(Badge: {u.get('badge_id')}, Role: {u.get('role')})"
        )
        _record_event("AUTH", f"Registered new employee: {u.get('name')}", True)
    else:
        tprint(f" [WEB AUTH] FAILED: {res.get('error')}")
    tprint("-" * 70)
    return res


def handle_attendance_log(
    user_id: str, name: str, badge_id: str, door_id: str, action: str
) -> dict:
    res = log_attendance(
        user_id=user_id, name=name, badge_id=badge_id, door_id=door_id, action=action
    )
    tprint(
        f"\n[ATTENDANCE] Employee '{name}' ({badge_id}) logged "
        f"'{action.upper()}' at '{door_id}'"
    )
    _record_event("ATTENDANCE", f"{name} {action} at {door_id}", True)
    return res


def handle_device_send(body: dict) -> dict:
    device_id = body.get("device_id")
    sensor_type = body.get("sensor_type")
    tprint(f"\n[WEB ACTION] Polling sensor reading: '{device_id}' ({sensor_type})...")
    try:
        private_key = load_device_private_key(device_id)
        message = _make_message(device_id, sensor_type)
        with tls_connect(DEFAULT_HOST, IOT_PORT) as conn:
            result = perform_handshake(
                conn, device_id, private_key, generate_key(), message, verify_server_sig=False
            )
        logs = _log_capture.flush_records()
        if result.get("status") == "OK":
            tprint(
                f"[TELEMETRY] Sensor '{device_id}' encrypted/signed telemetry: "
                f"{message['value']}"
            )
            _record_event("TELEMETRY", f"Polled {device_id}: {message['value']}", True)
            return {
                "ok": True,
                "value": message["value"],
                "office_state": get_office_state(),
                "logs": logs,
            }
        tprint(f"[TELEMETRY] Sensor '{device_id}' failed: {result.get('reason')}")
        return {"ok": False, "error": result.get("reason", "unknown"), "logs": logs}
    except Exception as e:
        logs = _log_capture.flush_records()
        tprint(f"[TELEMETRY] Error communicating with '{device_id}': {e}")
        return {"ok": False, "error": str(e), "logs": logs}


def handle_rbac_action(body: dict) -> dict:
    user_id = body.get("user_id", "employee_bob")
    role = body.get("role", "EMPLOYEE")
    action = body.get("action", "unlock")
    resource = body.get("resource", "door_main_entrance")
    device_id = body.get("device_id", resource)

    tprint("\n" + "=" * 70)
    tprint(f" [WEB ACCESS] Badge-In Request: User '{user_id}' (Role: {role})")
    tprint(f" [WEB ACCESS] Target Action   : '{action}' on Resource '{resource}'")
    tprint("=" * 70)

    try:
        private_key = load_device_private_key(device_id)
        message: Dict[str, Any] = {
            "device_id": device_id,
            "action": action,
            "resource": resource,
            "user_id": user_id,
            "role": role,
            "timestamp": time.time(),
            "message_id": str(uuid.uuid4()),
        }
        if "setpoint" in body:
            message["setpoint"] = body["setpoint"]

        with tls_connect(DEFAULT_HOST, IOT_PORT) as conn:
            result = perform_handshake(
                conn, device_id, private_key, generate_key(), message, verify_server_sig=False
            )

        logs = _log_capture.flush_records()
        is_ok = result.get("status") == "OK" and result.get("rbac") == "GRANTED"
        if is_ok:
            tprint(
                f" [DECISION] >>> RBAC GRANTED <<< Action '{action}' on '{resource}' "
                f"AUTHORIZED for {user_id}"
            )
            _record_event("RBAC", f"{user_id} ({role}) -> {action} {resource} GRANTED", True)
        else:
            tprint(f" [DECISION] >>> RBAC DENIED (403) <<< {result.get('reason', '')}")
            _record_event("RBAC", f"{user_id} ({role}) -> {action} {resource} DENIED", False)
            create_alert(
                level="WARNING",
                title=f"RBAC Access Denied ({resource})",
                message=(
                    f"User '{user_id}' ({role}) denied '{action}' on '{resource}': "
                    f"{result.get('reason', '')}"
                ),
                source="RBAC Policy Engine",
            )
        return {
            "ok": is_ok,
            "rbac": result.get("rbac", "DENIED" if not is_ok else "GRANTED"),
            "status": result.get("status"),
            "error_code": result.get("error_code"),
            "reason": result.get("reason", result.get("message", "")),
            "resource": resource,
            "action": action,
            "office_state": get_office_state(),
            "logs": logs,
        }
    except Exception as e:
        logs = _log_capture.flush_records()
        tprint(f" [ERROR] RBAC request error: {e}")
        return {"ok": False, "error": str(e), "logs": logs}


# ── Unified Attack Simulation Engine ──────────────────────────────────────────

ATTACK_METADATA = {
    "unauthorized": {
        "banner": "1. Rogue / Unregistered IoT Hardware Injection",
        "detail": "Attacker attempts to connect with unauthorized hardware ID 'rogue_office_spy'...",
        "alert_level": "WARNING",
        "alert_title": "Rogue Device Intercepted",
        "alert_msg": "Unregistered device 'rogue_office_spy' rejected during hardware handshake.",
        "alert_src": "Hardware Registry",
        "defense_msg": "Rogue hardware ID rejected at TLS/Hardware Registry check! Connection terminated.",
    },
    "tamper": {
        "banner": "2. In-Transit Ciphertext Bit-Flip Tampering",
        "detail": "Attacker modifies encrypted AES-256-GCM payload in transit...",
        "alert_level": "CRITICAL",
        "alert_title": "Tampered Ciphertext Intercepted",
        "alert_msg": "Malicious payload modification caught by AES-256-GCM authentication tag.",
        "alert_src": "Cryptographic Core",
        "defense_msg": "InvalidTag raised! AES-256-GCM 16-byte tag detected payload tampering. Dropped.",
    },
    "replay": {
        "banner": "3. Packet Replay Attack",
        "detail": "Attacker captures a valid unlock packet and replays it identically to server...",
        "alert_level": "WARNING",
        "alert_title": "Replay Attack Intercepted",
        "alert_msg": "Duplicate message_id rejected by anti-replay deduplication cache.",
        "alert_src": "Security Gateway",
        "defense_msg": "Duplicate message_id detected in replay window! Replayed packet dropped.",
    },
    "bad_signature": {
        "banner": "4. Forged Digital Signature (Untrusted Private Key)",
        "detail": "Attacker signs payload using an unauthorized ECC key...",
        "alert_level": "CRITICAL",
        "alert_title": "Forged Signature Intercepted",
        "alert_msg": "Unregistered ECDSA private key signature failed validation against trusted registry.",
        "alert_src": "Hardware Registry",
        "defense_msg": "ECDSA signature validation failed against trusted public key! Request rejected.",
    },
}


def handle_attack(attack_type: str) -> dict:
    """Execute one of the 4 simulated cryptographic/protocol attacks."""
    meta = ATTACK_METADATA.get(attack_type)
    if not meta:
        return {"ok": False, "error": f"Unknown attack type: {attack_type}", "logs": []}

    tprint("\n" + "=" * 70)
    tprint(f" [ATTACK SIMULATION] {meta['banner']}")
    tprint(f" {meta['detail']}")
    tprint("=" * 70)

    logs: List[str] = []
    rejected = False

    try:
        if attack_type == "unauthorized":
            with tls_connect(DEFAULT_HOST, IOT_PORT) as conn:
                send_json(conn, {"device_id": "rogue_office_spy"})
                resp = recv_json(conn)
                logs.append("[AUTH] Sent device_id: 'rogue_office_spy'")
                logs.append(f"[AUTH] Server response: {resp}")
                rejected = resp.get("status") == "REJECTED"

        elif attack_type == "tamper":
            device_id = "door_main_entrance"
            priv = load_device_private_key(device_id)
            msg = _make_message(device_id, "door")
            logs.append("[SECURITY] Maliciously flipping byte 0 of the AES-256-GCM ciphertext...")
            with tls_connect(DEFAULT_HOST, IOT_PORT) as conn:
                try:
                    resp = perform_handshake(
                        conn,
                        device_id,
                        priv,
                        generate_key(),
                        msg,
                        tamper_ciphertext=True,
                        verify_server_sig=False,
                    )
                    rejected = resp.get("status") == "ERROR"
                    logs.append(
                        f"[SECURITY] Server response: {resp.get('status')} — "
                        f"{resp.get('reason', '')[:60]}"
                    )
                except ConnectionError:
                    rejected = True
                    logs.append("[SECURITY] Server closed connection on tampered data.")

        elif attack_type == "replay":
            device_id = "door_main_entrance"
            priv = load_device_private_key(device_id)
            msg = _make_message(device_id, "door")
            logs.append(f"[SECURITY] Using message_id: {msg['message_id']}")
            for idx, label in enumerate(("First send", "Second send (replay)")):
                with tls_connect(DEFAULT_HOST, IOT_PORT) as conn:
                    resp = perform_handshake(
                        conn, device_id, priv, generate_key(), msg, verify_server_sig=False
                    )
                detail = f" — {resp.get('reason', '')[:60]}" if idx == 1 else ""
                logs.append(f"[SECURITY] {label}: {resp.get('status')}{detail}")
                if idx == 0:
                    tprint(
                        f" [ATTACK SIMULATION] Original send OK. Replaying message_id: "
                        f"{msg['message_id'][:8]}..."
                    )
                else:
                    rejected = resp.get("status") == "ERROR"

        elif attack_type == "bad_signature":
            device_id = "hvac_office"
            attacker_priv, _ = generate_ecc_keypair()
            msg = _make_message(device_id, "hvac")
            logs.append("[SECURITY] Signing with an UNREGISTERED private key...")
            with tls_connect(DEFAULT_HOST, IOT_PORT) as conn:
                resp = perform_handshake(
                    conn,
                    device_id,
                    attacker_priv,
                    generate_key(),
                    msg,
                    verify_server_sig=False,
                )
                rejected = resp.get("status") == "ERROR"
                logs.append(
                    f"[SECURITY] Server response: {resp.get('status')} — "
                    f"{resp.get('reason', '')[:80]}"
                )

        logs.append(f"[SECURITY] Result: {'REJECTED ✓' if rejected else 'NOT rejected ✗'}")
        if rejected:
            tprint(f" [DEFENSE TRIGGERED] {meta['defense_msg']}")
            record_blocked_attack()
            _record_event("SECURITY", f"Blocked {attack_type} attack", True)
            create_alert(
                level=meta["alert_level"],
                title=meta["alert_title"],
                message=meta["alert_msg"],
                source=meta["alert_src"],
            )
        _log_capture.flush_records()
        return {"ok": rejected, "attack": attack_type, "logs": logs}

    except Exception as e:
        logs.append(f"[ERROR] {e}")
        return {"ok": False, "attack": attack_type, "error": str(e), "logs": logs}


def handle_attack_all() -> dict:
    """Run all four attack simulations sequentially in a loop."""
    results = []
    combined_logs: List[str] = []
    for attack_type in ("unauthorized", "tamper", "replay", "bad_signature"):
        res = handle_attack(attack_type)
        results.append({"attack": attack_type, "ok": res.get("ok", False)})
        combined_logs.append(f"── {attack_type.upper()} ──")
        combined_logs.extend(res.get("logs", []))
    all_passed = all(r["ok"] for r in results)
    return {"ok": all_passed, "results": results, "logs": combined_logs}


def handle_alert_acknowledge(body: dict) -> dict:
    alert_id = body.get("alert_id", "")
    res = acknowledge_alert(alert_id)
    tprint(f"\n[ALERT ACK] Operator acknowledged alert: '{alert_id}'")
    return {"ok": True, "done": res}


def handle_alert_acknowledge_all() -> dict:
    count = acknowledge_all_alerts()
    tprint(f"\n[ALERT ACK] Operator acknowledged all open alerts ({count} updated).")
    return {"ok": True, "updated": count}


# ── HTTP request handler ──────────────────────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # suppress raw HTTP access log noise; structured events print via tprint

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path, content_type: str):
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            tprint(f"\n[HTTP] Dashboard Web UI accessed by client: {self.client_address[0]}")
            self._send_file(BASE_DIR / "dashboard" / "index.html", "text/html")
        elif path == "/api/users":
            safe_users = {
                uid: {
                    "name": u["name"],
                    "title": u["title"],
                    "role": u["role"].value,
                    "department": u["department"],
                    "badge_id": u["badge_id"],
                }
                for uid, u in USERS.items()
            }
            self._send_json({"ok": True, "users": safe_users})
        elif path == "/api/permissions":
            role = params.get("role", ["EMPLOYEE"])[0]
            self._send_json({"ok": True, "role": role, "permissions": get_role_permissions(role)})
        elif path == "/api/telemetry":
            self._send_json({"ok": True, "data": get_all_office_telemetry()})
        elif path == "/api/attendance":
            self._send_json({"ok": True, "records": get_recent_attendance()})
        elif path == "/api/assets":
            self._send_json({"ok": True, "assets": get_it_assets()})
        elif path == "/api/alerts":
            self._send_json({"ok": True, "alerts": get_alerts()})
        elif path == "/api/server/status":
            self._send_json({"ok": True, "running": _is_iot_running()})
        elif path == "/api/state":
            alerts = get_alerts()
            unread = sum(1 for a in alerts if not a.get("acknowledged"))
            self._send_json(
                {
                    "ok": True,
                    "running": _is_iot_running(),
                    "office_state": get_office_state(),
                    "rbac_stats": get_rbac_stats(),
                    "unread_alerts": unread,
                    "db_connected": is_db_connected(),
                    "recent_events": _recent_events[:12],
                }
            )
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        path = urlparse(self.path).path

        routes = {
            "/api/server/start": lambda: handle_server_start(),
            "/api/server/stop": lambda: handle_server_stop(),
            "/api/device/send": lambda: handle_device_send(body),
            "/api/rbac/action": lambda: handle_rbac_action(body),
            "/api/attack/unauthorized": lambda: handle_attack("unauthorized"),
            "/api/attack/tamper": lambda: handle_attack("tamper"),
            "/api/attack/replay": lambda: handle_attack("replay"),
            "/api/attack/bad_signature": lambda: handle_attack("bad_signature"),
            "/api/attack/all": lambda: handle_attack_all(),
            "/api/auth/login": lambda: handle_auth_login(
                body.get("email", ""), body.get("password", "")
            ),
            "/api/auth/register": lambda: handle_auth_register(
                name=body.get("name", ""),
                email=body.get("email", ""),
                password=body.get("password", ""),
                dept=body.get("department", "Engineering"),
                badge_id=body.get("badge_id"),
            ),
            "/api/attendance/log": lambda: handle_attendance_log(
                user_id=body.get("user_id", ""),
                name=body.get("name", ""),
                badge_id=body.get("badge_id", ""),
                door_id=body.get("door_id", "door_main_entrance"),
                action=body.get("action", "check-in"),
            ),
            "/api/alerts/create": lambda: {
                "ok": True,
                "alert": create_alert(
                    level=body.get("level", "INFO"),
                    title=body.get("title", ""),
                    message=body.get("message", ""),
                    source=body.get("source", "Dashboard"),
                ),
            },
            "/api/alerts/acknowledge": lambda: handle_alert_acknowledge(body),
            "/api/alerts/acknowledge_all": lambda: handle_alert_acknowledge_all(),
        }

        handler = routes.get(path)
        if handler:
            try:
                self._send_json(handler())
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)}, 500)
        else:
            self.send_response(404)
            self.end_headers()


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tprint("[DASHBOARD] Ensuring TLS certificates and Smart Office device keys...")
    ensure_tls_certificates()
    ensure_all_devices_registered()

    tprint("[DASHBOARD] Initializing database layer...")
    get_db()

    httpd = ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), _Handler)
    tprint("=" * 70)
    tprint(f" [DASHBOARD] Smart Office Dashboard running at http://localhost:{HTTP_PORT}")
    tprint(" [DASHBOARD] Admin login : admin@smartoffice.io / Admin@1234")
    tprint(" [DASHBOARD] Press Ctrl+C in this terminal to stop.")
    tprint("=" * 70)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        tprint("\n[DASHBOARD] Stopped.")
        if _iot_server:
            _iot_server.stop()
