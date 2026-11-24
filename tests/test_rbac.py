"""
tests/test_rbac.py
Unit tests for Role-Based Access Control (RBAC) in the Secure IoT Smart Office.
"""

import pytest
from crypto.rbac import (
    Role,
    USERS,
    get_user,
    is_action_permitted,
    evaluate_access_request,
    create_access_token,
)


def test_users_configured_correctly():
    """Verify administrator and employee accounts are present with expected roles."""
    alice = get_user("admin_alice")
    assert alice is not None
    assert alice["role"] == Role.ADMIN
    assert "Administrator" in alice["title"]

    bob = get_user("employee_bob")
    assert bob is not None
    assert bob["role"] == Role.EMPLOYEE

    charlie = get_user("guest_charlie")
    assert charlie is not None
    assert charlie["role"] == Role.GUEST


def test_admin_has_full_office_access():
    """Administrator Alice must be allowed access to all office zones and controls."""
    # Main entrance door
    allowed, _ = is_action_permitted(Role.ADMIN, "unlock", "door_main_entrance")
    assert allowed is True

    # High-security Server Room
    allowed, _ = is_action_permitted(Role.ADMIN, "unlock", "door_server_room")
    assert allowed is True

    # HVAC climate control configuration
    allowed, _ = is_action_permitted(Role.ADMIN, "configure", "hvac_office")
    assert allowed is True

    # Security audit logs
    allowed, _ = is_action_permitted(Role.ADMIN, "audit", "security_logs")
    assert allowed is True


def test_employee_can_access_general_office_areas():
    """Employee Bob must be allowed access to standard office zones and telemetry."""
    # Main entrance door
    allowed, _ = is_action_permitted(Role.EMPLOYEE, "unlock", "door_main_entrance")
    assert allowed is True

    # Reading climate telemetry
    allowed, _ = is_action_permitted(Role.EMPLOYEE, "read", "hvac_office")
    assert allowed is True

    # Reading meeting room presence
    allowed, _ = is_action_permitted(Role.EMPLOYEE, "read", "motion_meeting_room")
    assert allowed is True


def test_employee_denied_from_server_room():
    """Employee Bob must be DENIED when attempting to unlock the high-security Server Room."""
    allowed, reason = is_action_permitted(Role.EMPLOYEE, "unlock", "door_server_room")
    assert allowed is False
    assert "Server Room" in reason or "RBAC" in reason

    # Evaluation via PDP
    result = evaluate_access_request("employee_bob", "unlock", "door_server_room")
    assert result["allowed"] is False
    assert result["error_code"] == "RBAC_PERMISSION_DENIED"


def test_employee_denied_from_hvac_configuration():
    """Employee Bob must be DENIED from altering HVAC temperature setpoints."""
    allowed, reason = is_action_permitted(Role.EMPLOYEE, "configure", "hvac_office")
    assert allowed is False

    result = evaluate_access_request("employee_bob", "configure", "hvac_office")
    assert result["allowed"] is False
    assert result["error_code"] == "RBAC_PERMISSION_DENIED"


def test_employee_denied_from_security_audit():
    """Employee Bob must be DENIED from viewing security audit trails."""
    allowed, reason = is_action_permitted(Role.EMPLOYEE, "audit", "security_logs")
    assert allowed is False

    result = evaluate_access_request("employee_bob", "audit", "security_logs")
    assert result["allowed"] is False
    assert result["error_code"] == "RBAC_PERMISSION_DENIED"


def test_privilege_escalation_spoofing_prevented():
    """If an employee claims to be ADMIN, PDP must detect spoofing and reject."""
    result = evaluate_access_request(
        user_id="employee_bob",
        action="unlock",
        resource="door_server_room",
        claimed_role="ADMIN",  # Bob tries to impersonate an Admin!
    )
    assert result["allowed"] is False
    assert result["error_code"] == "ROLE_SPOOFING_DETECTED"
    assert "escalation" in result["reason"].lower()


def test_unknown_user_rejected():
    """An unknown user ID must be rejected by the PDP."""
    result = evaluate_access_request("unknown_intruder", "unlock", "door_main_entrance")
    assert result["allowed"] is False
    assert result["error_code"] == "USER_NOT_FOUND"


def test_access_token_creation():
    """Access token must carry user identity, assigned role, and action."""
    token = create_access_token("admin_alice", "unlock", "door_server_room")
    assert token["user_id"] == "admin_alice"
    assert token["role"] == "ADMIN"
    assert token["action"] == "unlock"
    assert token["resource"] == "door_server_room"
    assert "token_id" in token
    assert "timestamp" in token
