"""Pydantic schemas for Human Approval Workflow."""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict
from backend.app.db.models import ApprovalStatus


class ApprovalCreate(BaseModel):
    finding_id: Optional[int] = None
    target_asset: str
    proposed_test: str
    reason: str
    expected_impact: str
    rate_limit_rps: Optional[float] = 1.0
    validity_minutes: Optional[int] = 120


class ApprovalDecision(BaseModel):
    decision: str  # "APPROVED" or "REJECTED"
    reason: Optional[str] = None


class ApprovalOut(BaseModel):
    id: int
    finding_id: Optional[int]
    target_asset: str
    proposed_test: str
    reason: str
    expected_impact: str
    rate_limit_rps: float
    window_start: datetime
    window_end: datetime
    status: ApprovalStatus
    decision_reason: Optional[str]
    decided_by: Optional[str]
    decided_at: Optional[datetime]
    token: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)
