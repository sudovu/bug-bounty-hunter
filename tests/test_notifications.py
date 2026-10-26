"""Unit Tests for Email Notifications, Deduplication, and Secret Redaction."""
from datetime import datetime
from backend.app.core.security import generate_deduplication_hash
from backend.app.notifications.email_service import redact_sensitive_text, EmailService
from backend.app.db.models import Finding, FindingSeverity, FindingConfidence, FindingStatus, NotificationStatus


def test_secret_redaction():
    # Passwords
    raw_1 = "User login with password=SuperSecretPassword123! attempted"
    assert "SuperSecretPassword123!" not in redact_sensitive_text(raw_1)
    assert "[REDACTED]" in redact_sensitive_text(raw_1)

    # Bearer tokens
    raw_2 = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.somerandomtokendata"
    assert "somerandomtokendata" not in redact_sensitive_text(raw_2)
    assert "[REDACTED]" in redact_sensitive_text(raw_2)

    # API Keys
    raw_3 = "api_key='AIzaSyD-exampleKey123456'"
    assert "exampleKey123456" not in redact_sensitive_text(raw_3)
    assert "[REDACTED]" in redact_sensitive_text(raw_3)

    # Private key blocks
    raw_4 = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAz...dummy...\n-----END RSA PRIVATE KEY-----"
    assert "MIIEowIBAAKCAQEAz" not in redact_sensitive_text(raw_4)
    assert "[REDACTED_PRIVATE_KEY]" in redact_sensitive_text(raw_4)


def test_notification_deduplication_lifecycle(db_session, sample_program):
    finding = Finding(
        unique_finding_id="BB-TEST-0001",
        program_id=sample_program.id,
        asset="api.acme.example.com",
        category="Missing Defensive Security Header",
        title="Missing Content-Security-Policy (CSP) Header",
        description="CSP header is missing.",
        evidence_summary="Headers inspected: Server: nginx",
        detection_method="safe_passive_check",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.CONFIRMED,
        status=FindingStatus.DISCOVERED,
        deduplication_hash=generate_deduplication_hash("test", "finding")
    )
    db_session.add(finding)
    db_session.commit()

    # First alert attempt (simulated send)
    notif_1 = EmailService.send_finding_alert(
        db=db_session,
        finding=finding,
        program_name=sample_program.name
    )
    assert notif_1.status in [NotificationStatus.SENT, NotificationStatus.FAILED]

    # Manually mark as SENT to simulate successful transmission
    notif_1.status = NotificationStatus.SENT
    db_session.commit()

    # Second alert attempt for identical finding -> Must be flagged as SKIPPED_DUPLICATE
    notif_2 = EmailService.send_finding_alert(
        db=db_session,
        finding=finding,
        program_name=sample_program.name
    )
    assert notif_2.status == NotificationStatus.SKIPPED_DUPLICATE
    assert "Duplicate" in notif_2.error_message
