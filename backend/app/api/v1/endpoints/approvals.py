"""API Endpoints for Human Approvals (Mode C & Mode D)."""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.db.base import get_db
from backend.app.db.models import Approval, Program
from backend.app.schemas.approval import ApprovalCreate, ApprovalDecision, ApprovalOut
from backend.app.engine.approval_engine import create_approval_request, decide_approval
from backend.app.notifications.email_service import EmailService

router = APIRouter()


@router.get("", response_model=List[ApprovalOut])
def list_approvals(db: Session = Depends(get_db)):
    return db.query(Approval).order_by(Approval.created_at.desc()).all()


@router.post("", response_model=ApprovalOut, status_code=status.HTTP_201_CREATED)
def request_approval(payload: ApprovalCreate, db: Session = Depends(get_db)):
    """Initiate a formal approval request for an active test."""
    approval = create_approval_request(
        db=db,
        target_asset=payload.target_asset,
        proposed_test=payload.proposed_test,
        reason=payload.reason,
        expected_impact=payload.expected_impact,
        rate_limit_rps=payload.rate_limit_rps or 1.0,
        validity_minutes=payload.validity_minutes or 120,
        finding_id=payload.finding_id,
        requested_by="researcher"
    )

    # Trigger notification
    EmailService.send_approval_request_alert(
        db=db,
        approval_id=approval.id,
        target_asset=approval.target_asset,
        program_name="Target Program",
        proposed_test=approval.proposed_test,
        reason=approval.reason,
        expected_impact=approval.expected_impact,
        rate_limit_rps=approval.rate_limit_rps,
        window_start=approval.window_start,
        window_end=approval.window_end,
        token=approval.token
    )

    return approval


@router.post("/{approval_id}/decide", response_model=ApprovalOut)
def record_decision(
    approval_id: int,
    payload: ApprovalDecision,
    db: Session = Depends(get_db)
):
    """Approve or Reject an active testing request."""
    success, message, approval = decide_approval(
        db=db,
        approval_id=approval_id,
        decision=payload.decision,
        decided_by="admin_operator",
        decision_reason=payload.reason
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)

    return approval
