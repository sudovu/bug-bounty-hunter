"""Pydantic models for Scan Jobs and Findings."""
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict
from backend.app.db.models import (
    ScanMode, ScanStatus, FindingSeverity, FindingConfidence, FindingStatus
)


class ScanJobCreate(BaseModel):
    program_id: int
    target: str
    mode: ScanMode = ScanMode.SAFE_CHECKS
    profile_name: Optional[str] = "safe_default"


class ScanEventOut(BaseModel):
    id: int
    event_type: str
    message: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class ScanJobOut(BaseModel):
    id: int
    program_id: int
    target: str
    mode: ScanMode
    profile_name: str
    status: ScanStatus
    status_reason: Optional[str]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    created_at: datetime
    events: List[ScanEventOut] = []
    model_config = ConfigDict(from_attributes=True)


class FindingEvidenceOut(BaseModel):
    id: int
    evidence_type: str
    raw_evidence: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class FindingOut(BaseModel):
    id: int
    unique_finding_id: str
    program_id: int
    job_id: Optional[int]
    asset: str
    category: str
    title: str
    description: str
    evidence_summary: str
    affected_component: Optional[str]
    potential_impact: Optional[str]
    safe_reproduction: Optional[str]
    policy_reference: Optional[str]
    recommended_remediation: Optional[str]
    detection_method: str
    severity: FindingSeverity
    confidence: FindingConfidence
    status: FindingStatus
    discovered_at: datetime
    evidence_items: List[FindingEvidenceOut] = []
    model_config = ConfigDict(from_attributes=True)


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    notes: Optional[str] = None
