"""Human Approval Engine for Active Testing.

Enforces Mode C and Mode D approval workflows:
- Generates approval requests tied to exact targets, tests, and time windows.
- Validates active approval tokens.
- Ensures approvals cannot be reused for different tests, assets, or expired windows.
"""
from datetime import datetime, timedelta
from typing import Optional, Tuple
from sqlalchemy.orm import Session

from backend.app.core.security import generate_secure_token
from backend.app.core.audit import record_audit_event
from backend.app.db.models import (
    Approval, ApprovalEvent, ApprovalStatus, Finding, FindingStatus
)


def create_approval_request(
    db: Session,
    target_asset: str,
    proposed_test: str,
    reason: str,
    expected_impact: str,
    rate_limit_rps: float = 1.0,
    validity_minutes: int = 120,
    finding_id: Optional[int] = None,
    requested_by: str = "system"
) -> Approval:
    """Create a new human approval request bound to exact test parameters."""
    now = datetime.utcnow()
    window_end = now + timedelta(minutes=validity_minutes)
    token = generate_secure_token(prefix="appr")

    approval = Approval(
        finding_id=finding_id,
        target_asset=target_asset,
        proposed_test=proposed_test,
        reason=reason,
        expected_impact=expected_impact,
        rate_limit_rps=rate_limit_rps,
        window_start=now,
        window_end=window_end,
        status=ApprovalStatus.PENDING,
        token=token,
        created_at=now
    )
    db.add(approval)
    db.commit()
    db.refresh(approval)

    # If associated with a finding, update finding status
    if finding_id:
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if finding:
            finding.status = FindingStatus.AWAITING_APPROVAL
            db.commit()

    # Record event and audit log
    event = ApprovalEvent(
        approval_id=approval.id,
        actor=requested_by,
        action="APPROVAL_REQUESTED",
        details=f"Test '{proposed_test}' on target '{target_asset}' requested. Valid until {window_end.isoformat()}"
    )
    db.add(event)
    db.commit()

    record_audit_event(
        db,
        actor=requested_by,
        action="APPROVAL_REQUEST_CREATED",
        decision="PENDING",
        target=target_asset,
        reason=f"Approval requested for test '{proposed_test}'",
        metadata={"approval_id": approval.id, "window_end": window_end.isoformat()}
    )

    return approval


def decide_approval(
    db: Session,
    approval_id: int,
    decision: str,  # "APPROVED" or "REJECTED"
    decided_by: str,
    decision_reason: Optional[str] = None
) -> Tuple[bool, str, Optional[Approval]]:
    """Approve or reject a pending approval request."""
    approval = db.query(Approval).filter(Approval.id == approval_id).first()
    if not approval:
        return False, f"Approval request {approval_id} not found.", None

    if approval.status != ApprovalStatus.PENDING:
        return False, f"Approval is already in status '{approval.status.value}'.", approval

    if approval.window_end < datetime.utcnow():
        approval.status = ApprovalStatus.EXPIRED
        db.commit()
        return False, "Approval request has already expired.", approval

    if decision.upper() == "APPROVED":
        approval.status = ApprovalStatus.APPROVED
        if approval.finding:
            approval.finding.status = FindingStatus.APPROVED_FOR_VALIDATION
    else:
        approval.status = ApprovalStatus.REJECTED

    approval.decided_by = decided_by
    approval.decided_at = datetime.utcnow()
    approval.decision_reason = decision_reason or ""
    db.commit()

    # Record event
    event = ApprovalEvent(
        approval_id=approval.id,
        actor=decided_by,
        action=f"APPROVAL_{decision.upper()}",
        details=decision_reason or ""
    )
    db.add(event)
    db.commit()

    record_audit_event(
        db,
        actor=decided_by,
        action=f"APPROVAL_{decision.upper()}",
        decision=decision.upper(),
        target=approval.target_asset,
        reason=decision_reason or "",
        metadata={"approval_id": approval.id, "proposed_test": approval.proposed_test}
    )

    return True, f"Approval marked as {decision.upper()}.", approval


def validate_active_approval(
    db: Session,
    token: str,
    target_asset: str,
    proposed_test: str
) -> Tuple[bool, str]:
    """Verify that a valid, unexpired approval exists for the EXACT target and test."""
    approval = db.query(Approval).filter(Approval.token == token).first()
    if not approval:
        return False, "Invalid approval token."

    if approval.status != ApprovalStatus.APPROVED:
        return False, f"Approval status is '{approval.status.value}', not APPROVED."

    now = datetime.utcnow()
    if now < approval.window_start or now > approval.window_end:
        return False, "Current time is outside the authorized approval window."

    # Verify exact target matching
    if approval.target_asset.strip().lower() != target_asset.strip().lower():
        return False, f"Approval target '{approval.target_asset}' does not match requested target '{target_asset}'."

    # Verify exact test matching
    if approval.proposed_test.strip().lower() != proposed_test.strip().lower():
        return False, f"Approval test '{approval.proposed_test}' does not match requested test '{proposed_test}'."

    return True, "Valid authorization verified for exact target and test."
