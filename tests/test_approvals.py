"""Unit Tests for Human Approval Engine (Mode C & Mode D)."""
from datetime import datetime, timedelta
from backend.app.db.models import ApprovalStatus
from backend.app.engine.approval_engine import (
    create_approval_request,
    decide_approval,
    validate_active_approval
)


def test_approval_lifecycle(db_session):
    # 1. Request approval
    approval = create_approval_request(
        db=db_session,
        target_asset="api.example.com",
        proposed_test="Header reflection test",
        reason="Verify defense against header injection",
        expected_impact="Negligible, single test probe",
        rate_limit_rps=1.0,
        validity_minutes=60,
        requested_by="researcher_alice"
    )
    assert approval.id is not None
    assert approval.status == ApprovalStatus.PENDING
    token = approval.token

    # 2. Before approval, validation must FAIL
    valid, msg = validate_active_approval(
        db=db_session,
        token=token,
        target_asset="api.example.com",
        proposed_test="Header reflection test"
    )
    assert valid is False
    assert "not APPROVED" in msg

    # 3. Approve request
    success, msg, updated = decide_approval(
        db=db_session,
        approval_id=approval.id,
        decision="APPROVED",
        decided_by="lead_security_admin",
        decision_reason="Authorized within defined window"
    )
    assert success is True
    assert updated.status == ApprovalStatus.APPROVED

    # 4. With approval, validation must SUCCEED for exact match
    valid, msg = validate_active_approval(
        db=db_session,
        token=token,
        target_asset="api.example.com",
        proposed_test="Header reflection test"
    )
    assert valid is True

    # 5. Validation must FAIL if target differs
    valid, msg = validate_active_approval(
        db=db_session,
        token=token,
        target_asset="different.example.com",
        proposed_test="Header reflection test"
    )
    assert valid is False
    assert "does not match" in msg

    # 6. Validation must FAIL if proposed test differs
    valid, msg = validate_active_approval(
        db=db_session,
        token=token,
        target_asset="api.example.com",
        proposed_test="SQL Injection exploit"
    )
    assert valid is False
    assert "does not match" in msg


def test_approval_expiration(db_session):
    # Create request with window already expired
    approval = create_approval_request(
        db=db_session,
        target_asset="api.example.com",
        proposed_test="Safe probe",
        reason="Testing expiration",
        expected_impact="None",
        validity_minutes=10
    )
    # Manually backdate expiration
    approval.window_end = datetime.utcnow() - timedelta(minutes=5)
    db_session.commit()

    # Attempting to decide expired approval should mark it expired
    success, msg, _ = decide_approval(
        db=db_session,
        approval_id=approval.id,
        decision="APPROVED",
        decided_by="admin"
    )
    assert success is False
    assert "expired" in msg.lower()
