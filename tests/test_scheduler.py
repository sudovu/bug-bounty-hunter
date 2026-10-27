"""Tests for Automated Scheduler & Program Seeder (EWNet Scope)."""
import pytest
from sqlalchemy.orm import Session

from backend.app.db.models import Program, ScanJob, ScanStatus
from backend.app.engine.scheduler import seed_default_program, auto_scan_all_active_programs


def test_seed_default_program(db_session: Session):
    """Verify Everest Wireless Network program is seeded properly with in-scope assets and exclusion."""
    prog = seed_default_program(db_session)
    assert prog is not None
    assert "Everest Wireless Network" in prog.name
    assert prog.authorization_active is True
    assert len(prog.in_scope_assets) >= 1
    patterns = [a.pattern for a in prog.in_scope_assets]
    assert "ewnet.com.np" in patterns
    assert "*.ewnet.com.np" in patterns


def test_seed_default_program_idempotent(db_session: Session):
    """Ensure seeding multiple times does not create duplicates."""
    prog1 = seed_default_program(db_session)
    prog2 = seed_default_program(db_session)
    assert prog1.id == prog2.id
    count = db_session.query(Program).filter(Program.name.like("%Everest Wireless%")).count()
    assert count == 1


@pytest.mark.asyncio
async def test_auto_scan_all_active_programs(db_session: Session):
    """Verify auto_scan_all_active_programs scans only authorized ewnet targets."""
    seed_default_program(db_session)
    result = await auto_scan_all_active_programs(db_session)
    assert result["status"] == "completed"
    assert result["jobs_created"] >= 1

    jobs = db_session.query(ScanJob).all()
    assert len(jobs) >= 1
    for job in jobs:
        assert "ewnet.com.np" in job.target
