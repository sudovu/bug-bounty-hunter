"""Tests for Automated Scheduler & Program Seeder."""
import pytest
from sqlalchemy.orm import Session

from backend.app.db.models import Program, ScanJob, ScanStatus
from backend.app.engine.scheduler import seed_default_program, auto_scan_all_active_programs


def test_seed_default_program(db_session: Session):
    """Verify default demo program is seeded properly with in-scope asset and exclusion."""
    prog = seed_default_program(db_session)
    assert prog is not None
    assert prog.name == "Authorized Security Testing (Demo Scope)"
    assert prog.authorization_active is True
    assert len(prog.in_scope_assets) >= 1
    assert prog.in_scope_assets[0].pattern == "example.com"
    assert len(prog.excluded_assets) >= 1
    assert prog.excluded_assets[0].pattern == "internal.example.com"


def test_seed_default_program_idempotent(db_session: Session):
    """Ensure seeding multiple times does not create duplicates."""
    prog1 = seed_default_program(db_session)
    prog2 = seed_default_program(db_session)
    assert prog1.id == prog2.id
    count = db_session.query(Program).count()
    assert count == 1


@pytest.mark.asyncio
async def test_auto_scan_all_active_programs(db_session: Session):
    """Verify auto_scan_all_active_programs discovers targets and creates scan jobs."""
    seed_default_program(db_session)
    result = await auto_scan_all_active_programs(db_session)
    assert result["status"] == "completed"
    assert result["jobs_created"] >= 1

    jobs = db_session.query(ScanJob).all()
    assert len(jobs) >= 1
    assert jobs[0].status in [ScanStatus.COMPLETED, ScanStatus.RUNNING]
