"""
crypto/rbac.py
Role-Based Access Control (RBAC) engine for Secure IoT Smart Office.

Security Model:
───────────────
In an enterprise smart office, cryptographic protection (TLS 1.3, AES-256-GCM, ECDSA)
secures the transport and device identity, while RBAC enforces fine-grained user
authorization at the application layer.

Roles:
- ADMINISTRATOR (e.g. IT & Facilities Admin):
    * Full access to all office zones (Main Entrance, Server Room, Executive Boardroom).
    * Can read and modify HVAC climate setpoints and configuration.
    * Can view security audit logs and manage registered IoT devices.
- EMPLOYEE (e.g. Software Engineer, Staff):
    * Access to general office zones (Main Entrance, Meeting Rooms, Cafeteria).
    * Can view environmental telemetry (office temperature, meeting room occupancy).
    * Explicitly DENIED access to restricted high-security zones (Server Room).
    * Explicitly DENIED from modifying HVAC setpoints or accessing security logs.
"""

import threading
import time
import uuid
from enum import Enum
from typing import Tuple, Dict, Any, List, Optional


class Role(str, Enum):
    ADMIN = "ADMIN"
    EMPLOYEE = "EMPLOYEE"
    GUEST = "GUEST"


ROLE_CLEARANCE: Dict[Role, int] = {
    Role.GUEST: 1,
    Role.EMPLOYEE: 2,
    Role.ADMIN: 3,
}

_STATS_LOCK = threading.Lock()
_RBAC_STATS: Dict[str, int] = {
    "granted": 0,
    "denied": 0,
    "spoofing_blocked": 0,
    "unknown_user": 0,
}


def get_rbac_stats() -> Dict[str, int]:
    """Return a snapshot of RBAC policy enforcement counters."""
    with _STATS_LOCK:
        return dict(_RBAC_STATS)


def get_role_permissions(role_name: str) -> List[Dict[str, str]]:
    """Return the list of permitted (action, resource) pairs for a role."""
    try:
        role = Role(role_name.upper())
    except (ValueError, AttributeError):
        return []
    return [
        {"action": act, "resource": res}
        for act, res in sorted(PERMISSIONS.get(role, set()))
    ]


# ── Office Users ──────────────────────────────────────────────────────────────

USERS = {
    "admin_alice": {
        "name": "Alice Chen",
        "title": "IT & Facilities Administrator",
        "role": Role.ADMIN,
        "department": "Infrastructure & Security",
        "badge_id": "BADGE-ADM-001",
    },
    "employee_bob": {
        "name": "Bob Martinez",
        "title": "Software Engineer",
        "role": Role.EMPLOYEE,
        "department": "Engineering",
        "badge_id": "BADGE-EMP-104",
    },
    "guest_charlie": {
        "name": "Charlie Visitor",
        "title": "External Contractor",
        "role": Role.GUEST,
        "department": "Visitor",
        "badge_id": "BADGE-GST-999",
    },
}


# ── Smart Office Resources & Permissions Matrix ───────────────────────────────

# Actions:
# - unlock / lock : door access control
# - read          : read sensor data (telemetry)
# - configure     : modify device parameters (e.g. HVAC setpoints)
# - audit         : view security logs
# - manage        : add/remove IoT devices

PERMISSIONS = {
    Role.ADMIN: {
        # Doors
        ("unlock", "door_main_entrance"),
        ("lock", "door_main_entrance"),
        ("read", "door_main_entrance"),
        ("unlock", "door_server_room"),       # Restricted
        ("lock", "door_server_room"),         # Restricted
        ("read", "door_server_room"),
        # HVAC & Environment
        ("read", "hvac_office"),
        ("configure", "hvac_office"),         # Restricted (set temperature)
        ("read", "motion_meeting_room"),
        # Management & Audit
        ("audit", "security_logs"),           # Restricted
        ("manage", "iot_devices"),            # Restricted
        # Legacy device compatibility
        ("read", "temperature_01"),
        ("read", "motion_01"),
        ("read", "door_01"),
        ("unlock", "door_01"),
    },
    Role.EMPLOYEE: {
        # Doors: Main entrance only
        ("unlock", "door_main_entrance"),
        ("lock", "door_main_entrance"),
        ("read", "door_main_entrance"),
        # Reading office sensors is allowed
        ("read", "hvac_office"),
        ("read", "motion_meeting_room"),
        # Legacy device compatibility (read-only)
        ("read", "temperature_01"),
        ("read", "motion_01"),
        ("read", "door_01"),
        # Note: door_server_room and configure:hvac_office are deliberately omitted!
    },
    Role.GUEST: {
        # Guests can only read general meeting room presence
        ("read", "motion_meeting_room"),
    },
}


# ── Policy Enforcement Point (PEP) ────────────────────────────────────────────

def get_user(user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve user record by user_id."""
    u = USERS.get(user_id)
    if u is not None:
        return u
    try:
        from crypto.db import get_user_by_id
        db_user = get_user_by_id(user_id)
        if db_user:
            role_val = db_user.get("role", "EMPLOYEE")
            try:
                role_enum = Role(role_val)
            except (ValueError, TypeError):
                role_enum = Role.EMPLOYEE
            return {
                "name": db_user.get("name", user_id),
                "title": db_user.get("title", f"Staff ({db_user.get('department', 'General')})"),
                "role": role_enum,
                "department": db_user.get("department", "Staff"),
                "badge_id": db_user.get("badge_id", "BADGE-UNKNOWN"),
            }
    except Exception:
        pass
    return None


def is_action_permitted(role: Role, action: str, resource: str) -> Tuple[bool, str]:
    """
    Check if a given role is permitted to perform 'action' on 'resource'.
    Returns (is_allowed, reason).
    """
    role_perms = PERMISSIONS.get(role, set())

    # Check direct match or wildcard
    if (action, resource) in role_perms or ("*", resource) in role_perms or ("*", "*") in role_perms:
        return True, f"Role '{role.value}' is authorized to perform '{action}' on '{resource}'."

    # Specific informative denial reasons for smart office context
    if resource == "door_server_room" and action in ("unlock", "lock"):
        return False, (
            f"RBAC Policy Violation: Role '{role.value}' lacks clearance for high-security "
            f"Server Room access. Only 'ADMIN' role is authorized."
        )
    elif resource == "hvac_office" and action == "configure":
        return False, (
            f"RBAC Policy Violation: Role '{role.value}' cannot configure HVAC settings. "
            f"Facilities/Admin authorization required."
        )
    elif action == "audit":
        return False, (
            f"RBAC Policy Violation: Role '{role.value}' is not permitted to access security audit trails."
        )

    return False, f"RBAC Policy Violation: Role '{role.value}' has no permission '{action}' on '{resource}'."


def evaluate_access_request(
    user_id: str,
    action: str,
    resource: str,
    claimed_role: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Policy Decision Point (PDP) evaluating an access request.
    Verifies user identity, authenticates assigned role, and checks permissions.
    """
    user = get_user(user_id)
    if not user:
        with _STATS_LOCK:
            _RBAC_STATS["unknown_user"] += 1
        return {
            "allowed": False,
            "user_id": user_id,
            "role": "UNKNOWN",
            "action": action,
            "resource": resource,
            "error_code": "USER_NOT_FOUND",
            "reason": f"Unknown user identity '{user_id}'. Access denied.",
            "timestamp": time.time(),
        }

    actual_role = user["role"]

    # Prevent role spoofing / privilege escalation
    if claimed_role and claimed_role.upper() != actual_role.value:
        with _STATS_LOCK:
            _RBAC_STATS["spoofing_blocked"] += 1
        return {
            "allowed": False,
            "user_id": user_id,
            "role": actual_role.value,
            "action": action,
            "resource": resource,
            "error_code": "ROLE_SPOOFING_DETECTED",
            "reason": (
                f"Role escalation attempt detected: user '{user_id}' claimed role "
                f"'{claimed_role}', but registered role is '{actual_role.value}'."
            ),
            "timestamp": time.time(),
        }

    allowed, reason = is_action_permitted(actual_role, action, resource)
    with _STATS_LOCK:
        _RBAC_STATS["granted" if allowed else "denied"] += 1

    return {
        "allowed": allowed,
        "user_id": user_id,
        "user_name": user["name"],
        "role": actual_role.value,
        "department": user["department"],
        "action": action,
        "resource": resource,
        "error_code": None if allowed else "RBAC_PERMISSION_DENIED",
        "reason": reason,
        "timestamp": time.time(),
    }


def create_access_token(user_id: str, action: str, resource: str) -> Dict[str, Any]:
    """Generate a structured access token payload representing a user's intent."""
    user = get_user(user_id)
    role_str = user["role"].value if user else "UNKNOWN"
    return {
        "token_id": str(uuid.uuid4()),
        "user_id": user_id,
        "role": role_str,
        "action": action,
        "resource": resource,
        "timestamp": time.time(),
    }
