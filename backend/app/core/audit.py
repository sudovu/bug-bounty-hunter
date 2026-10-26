"""Security Audit Logging Service.

Maintains immutable logs of all authorization checks, scope verifications,
approvals, and operational state changes.
"""
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from backend.app.db.models import AuditLog


def record_audit_event(
    db: Session,
    actor: str,
    action: str,
    decision: str,
    target: Optional[str] = None,
    reason: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> AuditLog:
    """Record an immutable audit entry in the database."""
    log_entry = AuditLog(
        actor=actor,
        action=action,
        decision=decision,
        target=target,
        reason=reason,
        metadata_json=json.dumps(metadata or {}, default=str),
        created_at=datetime.now(timezone.utc)
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry
