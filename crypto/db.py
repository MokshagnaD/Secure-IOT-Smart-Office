"""
crypto/db.py
MongoDB Atlas Database Integration & Smart Office Data Layer.

Reads connection configuration from environment variables or a local `.env`
file (`MONGO_URI`, `MONGO_DB_NAME`) and falls back seamlessly to an in-memory
local cache when running offline or without MongoDB configured.

Features:
- Fixed Administrator account: admin@smartoffice.io / Admin@1234
- Dynamic Employee Registration and Authentication
- Employee Attendance Simulation and Logging
- Live Server Room & Climate Monitoring state persistence
- IT Asset Management inventory
- Centralized Alert Management
"""

import hashlib
import logging
import os
import random
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from pymongo import MongoClient
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False

log = logging.getLogger(__name__)
BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv() -> None:
    """Populate os.environ from project `.env` if present (without overwriting)."""
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()
MONGO_URI = os.environ.get("MONGO_URI", "").strip()
DB_NAME = os.environ.get("MONGO_DB_NAME", "smart_office_db").strip() or "smart_office_db"

_client: Optional[Any] = None
_db: Optional[Any] = None
_connected: bool = False
_mongo_attempted: bool = False
_state_lock = threading.Lock()

# ── In-Memory Fallback Cache (100% uptime offline or without MongoDB) ─────────
_local_cache: Dict[str, Any] = {
    "users": {},
    "attendance": [],
    "alerts": [],
    "assets": [],
}

# ── Live Stateful Smart Office Model ──────────────────────────────────────────
_office_state: Dict[str, Any] = {
    "door_main_entrance": "locked",
    "door_server_room": "locked",
    "hvac_office": {"temperature": 22.5, "setpoint": 22.0, "mode": "Auto (Optimized)"},
    "motion_meeting_room": "clear",
    "blocked_attacks": 0,
}


def update_office_state(resource: str, value: Any) -> None:
    """Update the live in-memory Smart Office device state."""
    with _state_lock:
        if resource == "hvac_office" and isinstance(value, dict):
            _office_state["hvac_office"].update(value)
        else:
            _office_state[resource] = value


def record_blocked_attack() -> int:
    """Increment and return the blocked attack counter."""
    with _state_lock:
        _office_state["blocked_attacks"] += 1
        return _office_state["blocked_attacks"]


def get_office_state() -> Dict[str, Any]:
    """Return a snapshot of live Smart Office doors, HVAC, motion, and security counts."""
    with _state_lock:
        return {
            "door_main_entrance": _office_state["door_main_entrance"],
            "door_server_room": _office_state["door_server_room"],
            "hvac_office": dict(_office_state["hvac_office"]),
            "motion_meeting_room": _office_state["motion_meeting_room"],
            "blocked_attacks": _office_state["blocked_attacks"],
        }


# ── Password Hashing Helpers ──────────────────────────────────────────────────

def hash_password(password: str, salt: Optional[str] = None) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 with 100,000 iterations."""
    if not salt:
        salt = os.urandom(16).hex()
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000,
    ).hex()
    return f"{salt}${hashed}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored salt$hash string."""
    try:
        salt, expected_hash = stored_hash.split("$")
        computed_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100000,
        ).hex()
        return computed_hash == expected_hash
    except Exception:
        return False


# ── Database Connection ───────────────────────────────────────────────────────

def get_db():
    """Initialize or return the MongoDB database handle (or None in local mode)."""
    global _client, _db, _connected, _mongo_attempted
    if _db is not None:
        return _db
    if _mongo_attempted:
        return None

    _mongo_attempted = True
    if not PYMONGO_AVAILABLE or not MONGO_URI:
        _seed_initial_data(use_local_only=True)
        return None

    try:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2500)
        _client.admin.command("ping")
        _db = _client[DB_NAME]
        _connected = True
        log.info("[DATABASE] Connected to MongoDB Atlas cluster successfully.")
        _seed_initial_data()
        return _db
    except Exception:
        log.warning("[DATABASE] MongoDB unreachable — running in fast Local Cache mode.")
        _seed_initial_data(use_local_only=True)
        return None


def is_db_connected() -> bool:
    """Check if MongoDB Atlas is actively connected."""
    return _connected


# ── Initial Seeding ───────────────────────────────────────────────────────────

FIXED_ADMIN = {
    "user_id": "admin_alice",
    "name": "Alice Chen",
    "email": "admin@smartoffice.io",
    "password_hash": hash_password("Admin@1234"),
    "role": "ADMIN",
    "department": "Infrastructure & Security",
    "badge_id": "BADGE-ADM-001",
    "title": "IT & Facilities Administrator",
    "created_at": time.time(),
}

DEFAULT_ASSETS = [
    {
        "asset_id": "AST-SRV-01",
        "name": "Primary Server Rack A1 (PowerEdge 750)",
        "category": "Servers",
        "ip_address": "10.0.1.10",
        "location": "Server Room (Rack 1)",
        "status": "Online",
        "uptime": "99.98%",
        "last_audit": "2026-11-15",
    },
    {
        "asset_id": "AST-SEC-02",
        "name": "Hardware Security Module (ECDSA P-256)",
        "category": "Security",
        "ip_address": "10.0.1.2",
        "location": "Server Room (Rack 1)",
        "status": "Online",
        "uptime": "100.0%",
        "last_audit": "2026-11-18",
    },
    {
        "asset_id": "AST-GW-03",
        "name": "Secure IoT Edge Gateway & TLS Proxy",
        "category": "IoT Gateway",
        "ip_address": "10.0.1.5",
        "location": "Comms Cabinet",
        "status": "Online",
        "uptime": "99.95%",
        "last_audit": "2026-11-18",
    },
    {
        "asset_id": "AST-UPS-04",
        "name": "APC Smart-UPS 3000VA Backup Unit",
        "category": "Infrastructure",
        "ip_address": "10.0.1.25",
        "location": "Server Room",
        "status": "Healthy (Battery 100%)",
        "uptime": "100.0%",
        "last_audit": "2026-11-10",
    },
    {
        "asset_id": "AST-WKS-05",
        "name": "Engineering Workstation Fleet Hub",
        "category": "Workstations",
        "ip_address": "10.0.2.0/24",
        "location": "Open Office Floor",
        "status": "Online (38 Active)",
        "uptime": "99.8%",
        "last_audit": "2026-11-14",
    },
]

DEFAULT_ALERTS = [
    {
        "alert_id": "ALT-1001",
        "level": "INFO",
        "title": "IoT Security Gateway Initialized",
        "message": "TLS 1.3 socket server ready on port 65432 with ECDSA P-256.",
        "source": "Security Core",
        "timestamp": time.time() - 3600,
        "acknowledged": True,
    },
    {
        "alert_id": "ALT-1002",
        "level": "INFO",
        "title": "HVAC Auto Climate Optimization",
        "message": "Office temperature regulated at 22.0°C setpoint.",
        "source": "Climate Controller",
        "timestamp": time.time() - 1800,
        "acknowledged": True,
    },
]


def _seed_initial_data(use_local_only: bool = False):
    """Seed the fixed admin user, default IT assets, and base alerts."""
    _local_cache["users"][FIXED_ADMIN["email"]] = FIXED_ADMIN
    if not _local_cache["assets"]:
        _local_cache["assets"].extend(dict(a) for a in DEFAULT_ASSETS)
    if not _local_cache["alerts"]:
        _local_cache["alerts"].extend(dict(a) for a in DEFAULT_ALERTS)

    if use_local_only or _db is None:
        return

    try:
        users_col = _db["users"]
        if not users_col.find_one({"email": FIXED_ADMIN["email"]}):
            users_col.insert_one(dict(FIXED_ADMIN))
            log.info("[DATABASE] Admin account seeded in MongoDB Atlas.")

        assets_col = _db["assets"]
        if assets_col.count_documents({}) == 0:
            assets_col.insert_many([dict(a) for a in DEFAULT_ASSETS])
            log.info("[DATABASE] Default IT assets seeded in MongoDB.")

        alerts_col = _db["alerts"]
        if alerts_col.count_documents({}) == 0:
            alerts_col.insert_many([dict(a) for a in DEFAULT_ALERTS])
    except Exception as e:
        log.warning(f"[DATABASE] Seeding error: {e}")


# ── User Registration & Authentication ────────────────────────────────────────

def register_employee(
    name: str,
    email: str,
    password: str,
    department: str,
    badge_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Register a new employee with role EMPLOYEE."""
    email = email.strip().lower()
    if not name or not email or not password:
        return {"ok": False, "error": "All fields (name, email, password) are required."}

    if not badge_id:
        badge_id = f"BADGE-EMP-{str(uuid.uuid4())[:4].upper()}"

    db = get_db()
    if db is not None:
        try:
            if db["users"].find_one({"email": email}):
                return {"ok": False, "error": f"An employee with email '{email}' already exists."}
        except Exception:
            pass

    if email in _local_cache["users"]:
        return {"ok": False, "error": f"An employee with email '{email}' already exists."}

    user_record = {
        "user_id": f"emp_{str(uuid.uuid4())[:8]}",
        "name": name.strip(),
        "email": email,
        "password_hash": hash_password(password),
        "role": "EMPLOYEE",
        "department": department or "Engineering",
        "badge_id": badge_id,
        "title": f"Staff Member ({department})",
        "created_at": time.time(),
    }

    if db is not None:
        try:
            db["users"].insert_one(dict(user_record))
            log.info(f"[DATABASE] Registered new employee in MongoDB: {name} ({email})")
        except Exception as e:
            log.warning(f"[DATABASE] Failed to write employee to MongoDB: {e}")

    _local_cache["users"][email] = user_record

    create_alert(
        level="INFO",
        title="New Employee Registered",
        message=f"{name} ({department}) registered with badge {badge_id}.",
        source="Identity Management",
    )

    return {
        "ok": True,
        "user": {
            "user_id": user_record["user_id"],
            "name": user_record["name"],
            "email": user_record["email"],
            "role": user_record["role"],
            "department": user_record["department"],
            "badge_id": user_record["badge_id"],
            "title": user_record["title"],
        },
    }


def authenticate_user(email: str, password: str) -> Dict[str, Any]:
    """Authenticate Administrator or Employee against MongoDB or local cache."""
    email = email.strip().lower()
    user = None

    db = get_db()
    if db is not None:
        try:
            user = db["users"].find_one({"email": email})
        except Exception as e:
            log.warning(f"[DATABASE] User lookup error: {e}")

    if not user:
        user = _local_cache["users"].get(email)

    if not user or not verify_password(password, user["password_hash"]):
        return {"ok": False, "error": "Invalid email or password."}

    return {
        "ok": True,
        "user": {
            "user_id": user["user_id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "department": user.get("department", "Staff"),
            "badge_id": user.get("badge_id", "BADGE-UNKNOWN"),
            "title": user.get("title", "Office Member"),
        },
    }


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Lookup a user by user_id."""
    db = get_db()
    if db is not None:
        try:
            u = db["users"].find_one({"user_id": user_id})
            if u:
                return u
        except Exception:
            pass
    for u in _local_cache["users"].values():
        if u["user_id"] == user_id:
            return u
    return None


# ── Employee Attendance Simulation ────────────────────────────────────────────

def log_attendance(
    user_id: str,
    name: str,
    badge_id: str,
    door_id: str,
    action: str = "check-in",
) -> Dict[str, Any]:
    """Log an attendance record when an employee badges in/out."""
    now = datetime.now()
    record = {
        "record_id": str(uuid.uuid4())[:8],
        "user_id": user_id,
        "name": name,
        "badge_id": badge_id,
        "door_id": door_id,
        "action": action,
        "timestamp": time.time(),
        "time_str": now.strftime("%H:%M:%S"),
        "date_str": now.strftime("%Y-%m-%d"),
        "status": "Present (On-Time)" if now.hour < 10 else "Present (Recorded)",
    }

    db = get_db()
    if db is not None:
        try:
            db["attendance"].insert_one(dict(record))
        except Exception as e:
            log.warning(f"[DATABASE] Failed to write attendance: {e}")

    _local_cache["attendance"].insert(0, record)
    return {"ok": True, "record": record}


def get_recent_attendance(limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieve recent attendance logs."""
    db = get_db()
    if db is not None:
        try:
            records = list(
                db["attendance"].find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
            )
            if records:
                return records
        except Exception:
            pass
    return _local_cache["attendance"][:limit]


# ── Alert Management ──────────────────────────────────────────────────────────

def create_alert(level: str, title: str, message: str, source: str) -> Dict[str, Any]:
    """Create a security or system alert."""
    alert = {
        "alert_id": f"ALT-{str(uuid.uuid4())[:4].upper()}",
        "level": level.upper(),
        "title": title,
        "message": message,
        "source": source,
        "timestamp": time.time(),
        "time_str": datetime.now().strftime("%H:%M:%S"),
        "acknowledged": False,
    }

    db = get_db()
    if db is not None:
        try:
            db["alerts"].insert_one(dict(alert))
        except Exception:
            pass

    _local_cache["alerts"].insert(0, alert)
    return alert


def get_alerts(limit: int = 30) -> List[Dict[str, Any]]:
    """Get active and historical alerts."""
    db = get_db()
    if db is not None:
        try:
            records = list(
                db["alerts"].find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
            )
            if records:
                return records
        except Exception:
            pass
    return _local_cache["alerts"][:limit]


def acknowledge_alert(alert_id: str) -> bool:
    """Acknowledge a single alert."""
    db = get_db()
    if db is not None:
        try:
            db["alerts"].update_one({"alert_id": alert_id}, {"$set": {"acknowledged": True}})
        except Exception:
            pass
    for a in _local_cache["alerts"]:
        if a["alert_id"] == alert_id:
            a["acknowledged"] = True
            return True
    return True


def acknowledge_all_alerts() -> int:
    """Acknowledge all open alerts and return count updated."""
    db = get_db()
    if db is not None:
        try:
            db["alerts"].update_many({"acknowledged": False}, {"$set": {"acknowledged": True}})
        except Exception:
            pass
    count = 0
    for a in _local_cache["alerts"]:
        if not a.get("acknowledged"):
            a["acknowledged"] = True
            count += 1
    return count


# ── IT Asset Management ───────────────────────────────────────────────────────

def get_it_assets() -> List[Dict[str, Any]]:
    """Retrieve the Smart Office IT asset inventory."""
    db = get_db()
    if db is not None:
        try:
            assets = list(db["assets"].find({}, {"_id": 0}))
            if assets:
                return assets
        except Exception:
            pass
    return _local_cache["assets"]


# ── Stateful Telemetry & Metrics Simulation ───────────────────────────────────

def get_all_office_telemetry() -> Dict[str, Any]:
    """
    Return stateful Smart Office telemetry synchronized with live door states
    and HVAC setpoint adjustments.
    """
    state = get_office_state()
    hvac = state["hvac_office"]
    setpoint = float(hvac.get("setpoint", 22.0))
    # Simulate realistic ambient drift around the active HVAC setpoint
    ambient_temp = round(setpoint + random.uniform(-0.4, 0.4), 1)
    srv_door_state = state["door_server_room"]

    return {
        "server_room": {
            "rack_temp": round(random.uniform(19.2, 20.8), 1),
            "humidity": round(random.uniform(40.0, 44.5), 1),
            "fan_speed_rpm": random.randint(3100, 3250),
            "chassis_status": "Healthy",
            "door_status": (
                "Unlocked (Admin Session Active)"
                if srv_door_state == "unlocked"
                else "Secured (Admin Keycard Required)"
            ),
            "ups_battery": "100%",
            "cctv_status": "Active (Recording)",
        },
        "climate": {
            "temperature": ambient_temp,
            "humidity": round(random.uniform(45.0, 52.0), 1),
            "air_quality_aqi": random.randint(28, 42),
            "co2_ppm": random.randint(480, 560),
            "hvac_mode": hvac.get("mode", "Auto (Optimized)"),
            "setpoint": setpoint,
        },
        "office_state": state,
        "db_status": {
            "connected": is_db_connected(),
            "mode": "MongoDB Atlas" if is_db_connected() else "Local Cache",
            "db_name": DB_NAME,
        },
    }
