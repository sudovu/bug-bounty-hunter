"""Scan Execution Orchestrator.

Manages end-to-end scan lifecycle:
- Scope & authorization gatekeeping
- Scanner execution under concurrency & timeouts
- Finding normalization, deduplication, and database persistence
- Alert notification dispatch
- Emergency stop monitoring
"""
import asyncio
from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session

from backend.app.core.emergency import emergency_control
from backend.app.core.security import generate_deduplication_hash, generate_secure_token
from backend.app.core.audit import record_audit_event
from backend.app.db.models import (
    ScanJob, ScanStatus, ScanEvent, Finding, FindingEvidence,
    FindingStatus, Program
)
from backend.app.engine.scope_engine import verify_target_authorization
from backend.app.scanners.base import BaseScanner, RawFindingCandidate
from backend.app.scanners.passive.security_headers import SecurityHeadersScanner
from backend.app.scanners.passive.tls_analyzer import TLSAnalyzerScanner
from backend.app.notifications.email_service import EmailService


class ScanOrchestrator:
    def __init__(self):
        # Register available safe scanners
        self.scanners: List[BaseScanner] = [
            SecurityHeadersScanner(timeout_seconds=20),
            TLSAnalyzerScanner(timeout_seconds=20)
        ]

    def add_job_event(self, db: Session, job_id: int, event_type: str, message: str) -> None:
        event = ScanEvent(job_id=job_id, event_type=event_type, message=message)
        db.add(event)
        db.commit()

    async def execute_job(self, db: Session, job_id: int) -> ScanJob:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not job:
            raise ValueError(f"Job {job_id} not found")

        # Check emergency stop
        if emergency_control.is_global_stopped():
            job.status = ScanStatus.STOPPED
            job.status_reason = "Operation aborted: Global Emergency Stop active"
            db.commit()
            return job

        job.status = ScanStatus.RUNNING
        job.started_at = datetime.utcnow()
        db.commit()

        self.add_job_event(db, job.id, "STATUS_CHANGE", f"Scan job started on target: {job.target}")

        # Mandatory Scope & Authorization Gate
        scope_result = verify_target_authorization(
            db=db,
            program_id=job.program_id,
            target=job.target,
            requested_mode=job.mode,
            actor="scanner_orchestrator"
        )

        if not scope_result.allowed:
            job.status = ScanStatus.BLOCKED_OUT_OF_SCOPE
            job.status_reason = scope_result.reason
            job.finished_at = datetime.utcnow()
            db.commit()
            self.add_job_event(db, job.id, "SCOPE_BLOCK", f"Scan blocked: {scope_result.reason}")
            return job

        # Execute registered safe scanners
        discovered_candidates: List[RawFindingCandidate] = []
        for scanner in self.scanners:
            if emergency_control.is_global_stopped():
                job.status = ScanStatus.STOPPED
                job.status_reason = "Scan interrupted by Global Emergency Stop"
                db.commit()
                return job

            self.add_job_event(db, job.id, "SCANNER_START", f"Running scanner: {scanner.name}")
            try:
                candidates = await scanner.run(
                    db=db,
                    program_id=job.program_id,
                    target=job.target,
                    actor="scanner_orchestrator"
                )
                discovered_candidates.extend(candidates)
                self.add_job_event(
                    db, job.id, "SCANNER_FINISH",
                    f"Scanner {scanner.name} completed. Found {len(candidates)} candidate(s)."
                )
            except Exception as e:
                self.add_job_event(
                    db, job.id, "SCANNER_ERROR",
                    f"Scanner {scanner.name} error: {str(e)}"
                )

        # Process and persist findings
        program = db.query(Program).filter(Program.id == job.program_id).first()
        program_name = program.name if program else f"Program-{job.program_id}"

        for cand in discovered_candidates:
            self._persist_finding(db, job, cand, program_name)

        job.status = ScanStatus.COMPLETED
        job.finished_at = datetime.utcnow()
        db.commit()

        self.add_job_event(
            db, job.id, "STATUS_CHANGE",
            f"Scan job completed successfully. Discovered {len(discovered_candidates)} item(s)."
        )
        return job

    def _persist_finding(
        self,
        db: Session,
        job: ScanJob,
        candidate: RawFindingCandidate,
        program_name: str
    ) -> Finding:
        """Deduplicate, record finding, store evidence, and send email alert."""
        dedup_hash = generate_deduplication_hash(
            str(job.program_id),
            candidate.category,
            candidate.title,
            candidate.affected_component or job.target
        )

        existing_finding = db.query(Finding).filter(
            Finding.program_id == job.program_id,
            Finding.deduplication_hash == dedup_hash
        ).first()

        now = datetime.utcnow()
        unique_id = f"BB-{now.strftime('%Y%m%d')}-{generate_secure_token(prefix='f')[:8].upper()}"

        finding = Finding(
            unique_finding_id=unique_id,
            program_id=job.program_id,
            job_id=job.id,
            asset=job.target,
            category=candidate.category,
            title=candidate.title,
            description=candidate.description,
            evidence_summary=candidate.evidence_summary,
            affected_component=candidate.affected_component,
            potential_impact=candidate.potential_impact,
            safe_reproduction=candidate.safe_reproduction,
            policy_reference=candidate.policy_reference,
            recommended_remediation=candidate.recommended_remediation,
            detection_method=candidate.detection_method,
            severity=candidate.severity,
            confidence=candidate.confidence,
            status=FindingStatus.DUPLICATE if existing_finding else FindingStatus.DISCOVERED,
            deduplication_hash=dedup_hash,
            duplicate_of_id=existing_finding.id if existing_finding else None,
            discovered_at=now
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)

        # Store sanitized evidence
        if candidate.raw_evidence:
            evidence = FindingEvidence(
                finding_id=finding.id,
                evidence_type="HTTP_TLS_INSPECTION",
                raw_evidence=candidate.raw_evidence,
                created_at=now
            )
            db.add(evidence)
            db.commit()

        # Dispatch email alert if new finding (not duplicate)
        if not existing_finding:
            EmailService.send_finding_alert(
                db=db,
                finding=finding,
                program_name=program_name
            )

        return finding


orchestrator = ScanOrchestrator()
