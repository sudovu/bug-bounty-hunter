"""API Endpoints for Scan Jobs."""
import asyncio
from typing import List
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session

from backend.app.db.base import get_db, SessionLocal
from backend.app.db.models import ScanJob, Program, ScanStatus
from backend.app.schemas.scan import ScanJobCreate, ScanJobOut
from backend.app.scanners.orchestrator import orchestrator

router = APIRouter()


async def run_scan_in_background(job_id: int):
    """Background runner for scan orchestrator."""
    db = SessionLocal()
    try:
        await orchestrator.execute_job(db, job_id)
    finally:
        db.close()


@router.get("", response_model=List[ScanJobOut])
def list_scan_jobs(program_id: int = None, db: Session = Depends(get_db)):
    query = db.query(ScanJob)
    if program_id:
        query = query.filter(ScanJob.program_id == program_id)
    return query.order_by(ScanJob.created_at.desc()).all()


@router.post("", response_model=ScanJobOut, status_code=status.HTTP_202_ACCEPTED)
def launch_scan_job(
    payload: ScanJobCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Enqueue and launch a new safety-checked scan job."""
    program = db.query(Program).filter(Program.id == payload.program_id).first()
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")

    job = ScanJob(
        program_id=payload.program_id,
        target=payload.target.strip(),
        mode=payload.mode,
        profile_name=payload.profile_name or "safe_default",
        status=ScanStatus.PENDING
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Launch execution asynchronously
    background_tasks.add_task(run_scan_in_background, job.id)

    return job


@router.get("/{job_id}", response_model=ScanJobOut)
def get_scan_job(job_id: int, db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job
