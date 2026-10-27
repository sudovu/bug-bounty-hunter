"""Automated Periodic Scan Scheduler & Program Seeder.

Provides:
- Automatic seeding of an authorized test program so the bot has an active program out-of-the-box.
- Background recurring scheduler that automatically audits authorized assets at configured intervals.
- Manual trigger API for on-demand automated scans across all active programs.
"""
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.emergency import emergency_control
from backend.app.db.base import SessionLocal
from backend.app.db.models import (
    Program, AuthorizedAsset, ExcludedAsset, AssetType,
    ScanJob, ScanStatus, ScanMode
)
from backend.app.engine.scope_engine import verify_target_authorization
from backend.app.scanners.orchestrator import orchestrator
from backend.app.core.audit import record_audit_event

logger = logging.getLogger(__name__)


def seed_default_program(db: Session, force: bool = False) -> Program:
    """Creates authorized Everest Wireless Network Pvt. Ltd. audit program if none exist."""
    ewnet_name = "Everest Wireless Network Pvt. Ltd. (EWNet Audit)"
    prog = db.query(Program).filter(Program.name == ewnet_name).first()
    if prog and not force:
        # Ensure any legacy demo program is deactivated
        demo_prog = db.query(Program).filter(Program.name == "Authorized Security Testing (Demo Scope)").first()
        if demo_prog and demo_prog.authorization_active:
            demo_prog.authorization_active = False
            db.commit()
        return prog

    # Deactivate any legacy demo programs
    demo_prog = db.query(Program).filter(Program.name == "Authorized Security Testing (Demo Scope)").first()
    if demo_prog and demo_prog.authorization_active:
        demo_prog.authorization_active = False

    program = Program(
        name=ewnet_name,
        platform="Organization Internal IT Audit",
        program_url="https://www.ewnet.com.np",
        policy_summary="Authorized defensive security & vulnerability audit for Everest Wireless Network Pvt. Ltd. (IT Officer: Bhuwan Gautam).",
        max_rate_limit=2.0,
        authorization_active=True,
    )
    db.add(program)
    db.commit()
    db.refresh(program)

    # In-scope assets for Everest Wireless Network Pvt. Ltd.
    assets_data = [
        (AssetType.DOMAIN, "ewnet.com.np", "Apex corporate domain"),
        (AssetType.WILDCARD, "*.ewnet.com.np", "All subdomains of Everest Wireless Network"),
        (AssetType.DOMAIN, "www.ewnet.com.np", "Primary public web portal"),
        (AssetType.DOMAIN, "mail.ewnet.com.np", "Organization mail exchange"),
        (AssetType.DOMAIN, "portal.ewnet.com.np", "Customer self-service portal"),
        (AssetType.DOMAIN, "billing.ewnet.com.np", "Billing / subscriber portal"),
    ]

    for atype, pattern, notes in assets_data:
        in_scope = AuthorizedAsset(
            program_id=program.id,
            asset_type=atype,
            pattern=pattern,
            allowed_methods="GET,HEAD",
            notes=notes
        )
        db.add(in_scope)

    # Excluded asset
    excluded = ExcludedAsset(
        program_id=program.id,
        pattern="sandbox-payment.ewnet.com.np",
        reason="Third party banking payment sandbox - excluded from automated probes"
    )
    db.add(excluded)

    db.commit()
    db.refresh(program)

    record_audit_event(
        db,
        actor="system_auto_seed",
        action="SEED_PROGRAM",
        decision="SUCCESS",
        target=program.name,
        reason="Initialized authorized Everest Wireless Network Pvt. Ltd. scope (ewnet.com.np and subdomains)."
    )
    logger.info(f"Seeded authorized organization program: {program.name} (ID: {program.id})")
    return program


async def auto_scan_all_active_programs(db: Session) -> Dict[str, Any]:
    """Iterates through all active authorized programs and runs safe scans on in-scope assets."""
    if emergency_control.is_global_stopped():
        logger.warning("Automated scan skipped: Global Emergency Stop is active.")
        return {"status": "skipped", "reason": "Emergency Stop Active", "jobs_created": 0}

    programs = db.query(Program).filter(Program.authorization_active == True).all()
    if not programs:
        logger.info("No active programs found for automatic scanning.")
        return {"status": "noop", "reason": "No active programs", "jobs_created": 0}

    jobs_launched = []
    target_filter = (getattr(settings, "AUTO_SCAN_TARGET_FILTER", "") or "").strip().lower()

    for prog in programs:
        for asset in prog.in_scope_assets:
            target = asset.pattern
            # Normalize target to standard domain/URL for scanning
            target_clean = target.lstrip("*.").strip()
            if not target_clean:
                continue

            # Strict filter: only scan targets associated with ewnet.com.np if filter is set
            if target_filter:
                host_norm = target_clean.lower()
                if not (host_norm == target_filter or host_norm.endswith("." + target_filter)):
                    logger.info(f"Auto-scan skipped non-ewnet target '{target_clean}' (filter: {target_filter})")
                    continue

            # Verify authorization gate
            scope_res = verify_target_authorization(
                db=db,
                program_id=prog.id,
                target=target_clean,
                requested_mode=ScanMode.SAFE_CHECKS,
                actor="auto_scheduler"
            )

            if not scope_res.allowed:
                logger.warning(f"Auto-scan target '{target_clean}' blocked: {scope_res.reason}")
                continue

            # Create scan job
            job = ScanJob(
                program_id=prog.id,
                target=target_clean,
                mode=ScanMode.SAFE_CHECKS,
                profile_name="auto_scheduled_safe_checks",
                status=ScanStatus.PENDING
            )
            db.add(job)
            db.commit()
            db.refresh(job)

            # Execute scan job
            try:
                await orchestrator.execute_job(db, job.id)
                jobs_launched.append({
                    "job_id": job.id,
                    "target": target_clean,
                    "status": job.status.value
                })
            except Exception as e:
                logger.error(f"Error executing auto scan job {job.id}: {e}")

    return {
        "status": "completed",
        "jobs_created": len(jobs_launched),
        "jobs": jobs_launched
    }


async def start_background_scheduler():
    """Background loop that executes periodic automated scans on active programs."""
    if not settings.AUTO_SCAN_ENABLED:
        logger.info("Automated periodic scheduler is disabled in settings.")
        return

    logger.info("Automated scan scheduler starting up...")
    # Initial sleep to allow database and server to fully initialize
    await asyncio.sleep(2)

    # Auto-seed if database has no programs
    if settings.AUTO_SEED_DEFAULT_PROGRAM:
        db = SessionLocal()
        try:
            seed_default_program(db)
        finally:
            db.close()

    # Initial scan run on startup
    db = SessionLocal()
    try:
        logger.info("Triggering initial startup auto-scan...")
        await auto_scan_all_active_programs(db)
    except Exception as e:
        logger.error(f"Startup auto-scan error: {e}")
    finally:
        db.close()

    # Recurring loop
    interval_seconds = max(settings.AUTO_SCAN_INTERVAL_MINUTES * 60, 60)
    logger.info(f"Automated scheduler running every {settings.AUTO_SCAN_INTERVAL_MINUTES} minutes.")

    while True:
        try:
            await asyncio.sleep(interval_seconds)
            if settings.AUTO_SCAN_ENABLED and not emergency_control.is_global_stopped():
                db = SessionLocal()
                try:
                    logger.info("Executing scheduled periodic scan cycle...")
                    await auto_scan_all_active_programs(db)
                finally:
                    db.close()
        except asyncio.CancelledError:
            logger.info("Automated scheduler background task cancelled.")
            break
        except Exception as e:
            logger.error(f"Unexpected error in background scheduler loop: {e}")
            await asyncio.sleep(30)
