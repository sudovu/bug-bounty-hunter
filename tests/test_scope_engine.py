"""Unit Tests for Scope and Authorization Engine."""
from datetime import datetime, timedelta
from unittest.mock import patch
from backend.app.core.emergency import emergency_control
from backend.app.db.models import ScanMode
from backend.app.engine.scope_engine import (
    verify_target_authorization,
    match_domain_pattern,
    match_cidr_pattern,
    match_url_pattern
)


def test_domain_and_wildcard_matching():
    # Exact match
    assert match_domain_pattern("example.com", "example.com") is True
    assert match_domain_pattern("other.com", "example.com") is False

    # Wildcard matches subdomains
    assert match_domain_pattern("api.example.com", "*.example.com") is True
    assert match_domain_pattern("sub.api.example.com", "*.example.com") is True

    # Wildcard does NOT match parent domain or unrelated domain
    assert match_domain_pattern("example.com", "*.example.com") is False
    assert match_domain_pattern("evilexample.com", "*.example.com") is False
    assert match_domain_pattern("not-example.com", "*.example.com") is False


def test_cidr_matching():
    assert match_cidr_pattern("198.51.100.5", "198.51.100.0/24") is True
    assert match_cidr_pattern("198.51.101.5", "198.51.100.0/24") is False


def test_url_pattern_matching():
    assert match_url_pattern("https://app.example.com/api/v1/users", "https://app.example.com/api") is True
    assert match_url_pattern("https://app.example.com/other", "https://app.example.com/api") is False
    assert match_url_pattern("http://app.example.com/api", "https://app.example.com/api") is False


@patch("backend.app.engine.scope_engine.validate_destination_safety")
def test_scope_verification_in_scope_allowed(mock_safety, db_session, sample_program):
    mock_safety.return_value = (True, "", ["93.184.216.34"])

    # Target in wildcard scope
    res = verify_target_authorization(
        db=db_session,
        program_id=sample_program.id,
        target="api.acme.example.com",
        requested_mode=ScanMode.PASSIVE
    )
    assert res.allowed is True
    assert res.decision == "ALLOW"
    assert "Matched in-scope wildcard" in res.reason


@patch("backend.app.engine.scope_engine.validate_destination_safety")
def test_scope_verification_exclusion_overrides_scope(mock_safety, db_session, sample_program):
    mock_safety.return_value = (True, "", ["93.184.216.34"])

    # Target would match *.acme.example.com, BUT is explicitly excluded
    res = verify_target_authorization(
        db=db_session,
        program_id=sample_program.id,
        target="admin.acme.example.com",
        requested_mode=ScanMode.PASSIVE
    )
    assert res.allowed is False
    assert res.decision == "DENY"
    assert "Explicitly excluded from scope" in res.reason


@patch("backend.app.engine.scope_engine.validate_destination_safety")
def test_scope_verification_out_of_scope_rejected(mock_safety, db_session, sample_program):
    mock_safety.return_value = (True, "", ["93.184.216.34"])

    # Target completely outside scope
    res = verify_target_authorization(
        db=db_session,
        program_id=sample_program.id,
        target="attacker.com",
        requested_mode=ScanMode.PASSIVE
    )
    assert res.allowed is False
    assert res.decision == "DENY"
    assert "not in authorized scope allowlist" in res.reason


@patch("backend.app.engine.scope_engine.validate_destination_safety")
def test_scope_verification_expired_authorization(mock_safety, db_session, sample_program):
    mock_safety.return_value = (True, "", ["93.184.216.34"])

    # Expire authorization
    sample_program.authorization_expires_at = datetime.utcnow() - timedelta(days=1)
    db_session.commit()

    res = verify_target_authorization(
        db=db_session,
        program_id=sample_program.id,
        target="api.acme.example.com",
        requested_mode=ScanMode.PASSIVE
    )
    assert res.allowed is False
    assert res.decision == "DENY"
    assert "expired" in res.reason.lower()


def test_scope_verification_emergency_stop_blocks_all(db_session, sample_program):
    emergency_control.trigger_global_stop()

    res = verify_target_authorization(
        db=db_session,
        program_id=sample_program.id,
        target="api.acme.example.com",
        requested_mode=ScanMode.PASSIVE
    )
    assert res.allowed is False
    assert res.decision == "DENY"
    assert "Global emergency stop is ACTIVE" in res.reason
