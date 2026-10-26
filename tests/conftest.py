"""Pytest Configuration and Shared Test Fixtures."""
import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sqlalchemy.pool import StaticPool
from backend.app.db.base import Base
from backend.app.db.models import (
    Program, AuthorizedAsset, ExcludedAsset, AssetType, ScanMode
)
from backend.app.core.emergency import emergency_control


@pytest.fixture(autouse=True)
def reset_emergency_stop():
    """Ensure emergency stop is reset to operational state before every test."""
    emergency_control.resume_global_stop()
    yield
    emergency_control.resume_global_stop()


@pytest.fixture
def db_session():
    """Create an isolated in-memory SQLite database for test execution."""
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def sample_program(db_session):
    """Seed an authorized test program with scope rules and exclusions."""
    prog = Program(
        name="Acme Security Bounty",
        platform="HackerOne",
        program_url="https://hackerone.com/acme",
        policy_summary="Responsible disclosure on public cloud assets.",
        authorization_active=True,
        authorization_expires_at=datetime.utcnow() + timedelta(days=30),
        max_rate_limit=2.0
    )
    db_session.add(prog)
    db_session.commit()
    db_session.refresh(prog)

    # In-scope: *.acme.example.com and specific domain portal.example.com
    in_scope_1 = AuthorizedAsset(
        program_id=prog.id,
        asset_type=AssetType.WILDCARD,
        pattern="*.acme.example.com"
    )
    in_scope_2 = AuthorizedAsset(
        program_id=prog.id,
        asset_type=AssetType.DOMAIN,
        pattern="portal.example.com"
    )
    # Excluded: admin.acme.example.com and internal.acme.example.com
    excluded_1 = ExcludedAsset(
        program_id=prog.id,
        pattern="admin.acme.example.com",
        reason="Admin console strictly out of scope"
    )
    excluded_2 = ExcludedAsset(
        program_id=prog.id,
        pattern="*.internal.example.com",
        reason="Internal networks out of scope"
    )

    db_session.add_all([in_scope_1, in_scope_2, excluded_1, excluded_2])
    db_session.commit()
    db_session.refresh(prog)
    return prog
