"""API Endpoints for System Status, Emergency Stop, and Audit Logs."""
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.orm import Session

from backend.app.db.base import get_db, SessionLocal
from backend.app.core.emergency import emergency_control
from backend.app.core.config import settings
from backend.app.db.models import AuditLog, EmailNotification, ScanJob, Finding, Program
from backend.app.notifications.email_service import EmailService
from backend.app.engine.scheduler import auto_scan_all_active_programs, seed_default_program

router = APIRouter()


@router.get("/status")
def get_system_status(db: Session = Depends(get_db)):
    """Retrieve operational state, emergency stop flags, and counts."""
    return {
        "emergency_stop": emergency_control.is_global_stopped(),
        "email_notifications_enabled": settings.EMAIL_NOTIFICATIONS_ENABLED,
        "smtp_configured": bool(settings.SMTP_HOST),
        "total_programs": db.query(Program).filter(Program.authorization_active == True).count(),
        "total_jobs": db.query(ScanJob).count(),
        "total_findings": db.query(Finding).count(),
        "total_notifications": db.query(EmailNotification).count(),
        "total_audit_events": db.query(AuditLog).count(),
        "auto_scan_enabled": settings.AUTO_SCAN_ENABLED,
        "auto_scan_interval_minutes": settings.AUTO_SCAN_INTERVAL_MINUTES
    }


@router.post("/emergency-stop")
def toggle_emergency_stop(active: bool):
    """Trigger or disengage global emergency stop."""
    if active:
        emergency_control.trigger_global_stop()
    else:
        emergency_control.resume_global_stop()
    return {"emergency_stop": emergency_control.is_global_stopped()}


@router.post("/test-email")
def send_test_email(to_email: str = None):
    """Dispatch a test email to verify SMTP configuration."""
    recipient = to_email or settings.ALERT_TO_EMAIL
    success, error = EmailService.send_email_raw(
        to_email=recipient,
        subject="[BUG BOUNTY BOT] Test Alert Notification",
        body_text="This is a test notification from the Bug Bounty Hunter Bot. SMTP delivery is working correctly."
    )
    return {
        "success": success,
        "recipient": recipient,
        "error": error
    }


@router.get("/audit-logs")
def get_audit_logs(limit: int = 100, db: Session = Depends(get_db)):
    """Query recent immutable security audit logs."""
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    return logs


@router.post("/seed-demo")
def seed_demo_program_endpoint(force: bool = False, db: Session = Depends(get_db)):
    """Seed the default authorized demo program with in-scope target asset."""
    prog = seed_default_program(db, force=force)
    return {
        "status": "success",
        "program_id": prog.id,
        "name": prog.name,
        "platform": prog.platform
    }


async def _background_auto_scan():
    db = SessionLocal()
    try:
        await auto_scan_all_active_programs(db)
    finally:
        db.close()


@router.post("/auto-scan/trigger")
def trigger_auto_scan(background_tasks: BackgroundTasks):
    """Trigger an immediate automated scan across all active authorized programs."""
    background_tasks.add_task(_background_auto_scan)
    return {"status": "enqueued", "message": "Automated scan job triggered across all active programs."}
