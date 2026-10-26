"""API Endpoints for Generating and Downloading Vulnerability Reports."""
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from backend.app.db.base import get_db
from backend.app.db.models import VulnerabilityReport, Finding
from backend.app.reports.generator import create_and_save_report

router = APIRouter()


@router.get("")
def list_reports(db: Session = Depends(get_db)):
    return db.query(VulnerabilityReport).order_by(VulnerabilityReport.created_at.desc()).all()


@router.post("/generate/{finding_id}")
def generate_report(finding_id: int, db: Session = Depends(get_db)):
    try:
        report = create_and_save_report(db, finding_id)
        return report
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{report_id}/download", response_class=PlainTextResponse)
def download_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(VulnerabilityReport).filter(VulnerabilityReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report.content
