"""API Endpoints for Managing Security Findings."""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.db.base import get_db
from backend.app.db.models import Finding, FindingStatus, FindingSeverity
from backend.app.schemas.scan import FindingOut, FindingStatusUpdate
from backend.app.core.audit import record_audit_event

router = APIRouter()


@router.get("", response_model=List[FindingOut])
def list_findings(
    program_id: Optional[int] = None,
    severity: Optional[FindingSeverity] = None,
    status: Optional[FindingStatus] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Finding)
    if program_id:
        query = query.filter(Finding.program_id == program_id)
    if severity:
        query = query.filter(Finding.severity == severity)
    if status:
        query = query.filter(Finding.status == status)

    return query.order_by(Finding.discovered_at.desc()).all()


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}/status", response_model=FindingOut)
def update_finding_status(
    finding_id: int,
    payload: FindingStatusUpdate,
    db: Session = Depends(get_db)
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    old_status = finding.status
    finding.status = payload.status
    db.commit()
    db.refresh(finding)

    record_audit_event(
        db,
        actor="reviewer",
        action="FINDING_STATUS_UPDATE",
        decision=payload.status.value,
        target=finding.unique_finding_id,
        reason=payload.notes or f"Status changed from {old_status.value} to {payload.status.value}"
    )

    return finding
