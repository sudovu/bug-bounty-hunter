"""Email Notification Service with Deduplication, Redaction, and In-App Fallback."""
import re
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.security import generate_deduplication_hash
from backend.app.db.models import EmailNotification, NotificationStatus, Finding
from backend.app.notifications.templates import (
    FINDING_ALERT_SUBJECT,
    FINDING_ALERT_TEXT_TEMPLATE,
    APPROVAL_REQUEST_SUBJECT,
    APPROVAL_REQUEST_TEXT_TEMPLATE,
    SCOPE_BLOCKED_ALERT_SUBJECT,
    SCOPE_BLOCKED_ALERT_TEXT_TEMPLATE,
)

# Common secret regex patterns for redacting sensitive content in alerts
SECRET_REDACT_PATTERNS = [
    (r'(?i)(password\s*[:=]\s*)["\']?([^"\'\s&]+)["\']?', r'\1[REDACTED]'),
    (r'(?i)(bearer\s+)[a-zA-Z0-9_\-\.]{15,}', r'\1[REDACTED]'),
    (r'(?i)(api[_-]?key\s*[:=]\s*)["\']?([^"\'\s&]+)["\']?', r'\1[REDACTED]'),
    (r'(?i)(secret\s*[:=]\s*)["\']?([^"\'\s&]+)["\']?', r'\1[REDACTED]'),
    (r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----', '[REDACTED_PRIVATE_KEY]'),
]


def redact_sensitive_text(text: str) -> str:
    """Sanitize strings to ensure credentials, tokens, or keys are never transmitted."""
    if not text:
        return ""
    sanitized = text
    for pattern, replacement in SECRET_REDACT_PATTERNS:
        sanitized = re.sub(pattern, replacement, sanitized)
    return sanitized


class EmailService:
    @staticmethod
    def send_email_raw(to_email: str, subject: str, body_text: str) -> Tuple[bool, Optional[str]]:
        """Dispatch email over SMTP if enabled, otherwise simulate safely."""
        if not settings.EMAIL_NOTIFICATIONS_ENABLED or not settings.SMTP_HOST:
            return False, "SMTP is disabled or not configured in environment settings."

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = settings.ALERT_FROM_EMAIL
            msg["To"] = to_email

            part = MIMEText(body_text, "plain")
            msg.attach(part)

            if settings.SMTP_USE_TLS:
                server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10)
                server.starttls()
            else:
                server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10)

            if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)

            server.sendmail(settings.ALERT_FROM_EMAIL, [to_email], msg.as_string())
            server.quit()
            return True, None
        except Exception as e:
            return False, f"SMTP delivery failed: {str(e)}"

    @classmethod
    def send_finding_alert(
        cls,
        db: Session,
        finding: Finding,
        program_name: str,
        dashboard_base_url: str = "http://localhost:8000"
    ) -> EmailNotification:
        """Deliver or record finding alert with deduplication."""
        dedup_key = generate_deduplication_hash(
            "finding_alert",
            str(finding.program_id),
            finding.category,
            finding.asset,
            finding.title
        )

        # Check deduplication
        existing = db.query(EmailNotification).filter(
            EmailNotification.deduplication_key == dedup_key,
            EmailNotification.status == NotificationStatus.SENT
        ).first()

        subject = FINDING_ALERT_SUBJECT.format(
            severity=finding.severity.value,
            program_name=program_name,
            title=finding.title
        )

        body_raw = FINDING_ALERT_TEXT_TEMPLATE.format(
            program_name=program_name,
            asset=finding.asset,
            title=finding.title,
            severity=finding.severity.value,
            confidence=finding.confidence.value,
            affected_component=finding.affected_component or "Not specified",
            evidence_summary=finding.evidence_summary,
            potential_impact=finding.potential_impact or "Under evaluation",
            safe_reproduction=finding.safe_reproduction or "Safe non-invasive inspection",
            policy_reference=finding.policy_reference or "Standard responsible disclosure",
            recommended_remediation=finding.recommended_remediation or "Follow security hardening guidelines",
            approval_required="YES" if finding.status.value == "AWAITING_APPROVAL" else "NO",
            unique_finding_id=finding.unique_finding_id,
            dashboard_url=f"{dashboard_base_url}/#findings"
        )
        body = redact_sensitive_text(body_raw)

        if existing:
            # Skip sending duplicate notification
            notification = EmailNotification(
                recipient=settings.ALERT_TO_EMAIL,
                subject=subject,
                notification_type="NEW_FINDING",
                deduplication_key=dedup_key,
                status=NotificationStatus.SKIPPED_DUPLICATE,
                body_text=body,
                error_message="Skipped: Duplicate finding already notified previously.",
                attempts=0
            )
            db.add(notification)
            db.commit()
            return notification

        success, error_msg = cls.send_email_raw(settings.ALERT_TO_EMAIL, subject, body)

        notification = EmailNotification(
            recipient=settings.ALERT_TO_EMAIL,
            subject=subject,
            notification_type="NEW_FINDING",
            deduplication_key=dedup_key,
            status=NotificationStatus.SENT if success else NotificationStatus.FAILED,
            body_text=body,
            error_message=error_msg,
            attempts=1,
            sent_at=datetime.utcnow() if success else None
        )
        db.add(notification)
        db.commit()
        db.refresh(notification)
        return notification

    @classmethod
    def send_approval_request_alert(
        cls,
        db: Session,
        approval_id: int,
        target_asset: str,
        program_name: str,
        proposed_test: str,
        reason: str,
        expected_impact: str,
        rate_limit_rps: float,
        window_start: datetime,
        window_end: datetime,
        token: str,
        dashboard_base_url: str = "http://localhost:8000"
    ) -> EmailNotification:
        """Notify researcher that an active test is requesting explicit approval."""
        dedup_key = generate_deduplication_hash("approval_request", str(approval_id), token)

        subject = APPROVAL_REQUEST_SUBJECT.format(
            target_asset=target_asset,
            program_name=program_name
        )

        body_raw = APPROVAL_REQUEST_TEXT_TEMPLATE.format(
            program_name=program_name,
            target_asset=target_asset,
            proposed_test=proposed_test,
            reason=reason,
            expected_impact=expected_impact,
            rate_limit_rps=rate_limit_rps,
            window_start=window_start.strftime("%Y-%m-%d %H:%M:%S UTC"),
            window_end=window_end.strftime("%Y-%m-%d %H:%M:%S UTC"),
            token=token,
            dashboard_url=f"{dashboard_base_url}/#approvals"
        )
        body = redact_sensitive_text(body_raw)

        success, error_msg = cls.send_email_raw(settings.ALERT_TO_EMAIL, subject, body)

        notification = EmailNotification(
            recipient=settings.ALERT_TO_EMAIL,
            subject=subject,
            notification_type="APPROVAL_REQUEST",
            deduplication_key=dedup_key,
            status=NotificationStatus.SENT if success else NotificationStatus.FAILED,
            body_text=body,
            error_message=error_msg,
            attempts=1,
            sent_at=datetime.utcnow() if success else None
        )
        db.add(notification)
        db.commit()
        db.refresh(notification)
        return notification
