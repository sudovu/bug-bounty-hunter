"""SQLAlchemy Database Models for Bug Bounty Hunter Bot.

Implements all entities for:
- Users & Roles
- Programs, Policies, Scope (Authorized Assets & Exclusions)
- Scan Profiles, Jobs, & Events
- Findings, Evidence, & Status Tracking
- Human Approval Workflows & Events
- Notifications & Deduplication
- Immutable Security Audit Logs
- Generated Vulnerability Reports
"""
import enum
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, Float, DateTime,
    ForeignKey, Enum, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship
from backend.app.db.base import Base


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    REVIEWER = "reviewer"
    READONLY = "readonly"


class AssetType(str, enum.Enum):
    DOMAIN = "DOMAIN"
    WILDCARD = "WILDCARD"
    URL = "URL"
    CIDR = "CIDR"
    REPOSITORY = "REPOSITORY"


class ScanMode(str, enum.Enum):
    PASSIVE = "PASSIVE"
    SAFE_CHECKS = "SAFE_CHECKS"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"
    BLOCKED_OUT_OF_SCOPE = "BLOCKED_OUT_OF_SCOPE"
    BLOCKED_EXPIRED = "BLOCKED_EXPIRED"


class FindingSeverity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingConfidence(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"


class FindingStatus(str, enum.Enum):
    DISCOVERED = "DISCOVERED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED_FOR_VALIDATION = "APPROVED_FOR_VALIDATION"
    VALIDATED = "VALIDATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    DUPLICATE = "DUPLICATE"
    REPORT_READY = "REPORT_READY"
    SUBMITTED_MANUALLY = "SUBMITTED_MANUALLY"
    RESOLVED = "RESOLVED"


class ApprovalStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class NotificationStatus(str, enum.Enum):
    PENDING = "PENDING"
    SENT = "SENT"
    FAILED = "FAILED"
    SKIPPED_DUPLICATE = "SKIPPED_DUPLICATE"


# -------------------------------------------------------------
# 1. User Model
# -------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.REVIEWER, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


# -------------------------------------------------------------
# 2. Program & Scope Models
# -------------------------------------------------------------
class Program(Base):
    __tablename__ = "programs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False, unique=True, index=True)
    platform = Column(String(100), nullable=False)  # HackerOne, Bugcrowd, Intigriti, Self-hosted, etc.
    program_url = Column(String(500), nullable=False)
    policy_summary = Column(Text, nullable=True)
    max_rate_limit = Column(Float, default=2.0)  # Max requests per second
    authorization_active = Column(Boolean, default=True)
    authorization_expires_at = Column(DateTime, nullable=True)
    last_scope_verification = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    in_scope_assets = relationship("AuthorizedAsset", back_populates="program", cascade="all, delete-orphan")
    excluded_assets = relationship("ExcludedAsset", back_populates="program", cascade="all, delete-orphan")
    scan_jobs = relationship("ScanJob", back_populates="program", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="program", cascade="all, delete-orphan")


class AuthorizedAsset(Base):
    """In-scope target definition for a program."""
    __tablename__ = "authorized_assets"

    id = Column(Integer, primary_key=True, index=True)
    program_id = Column(Integer, ForeignKey("programs.id", ondelete="CASCADE"), nullable=False)
    asset_type = Column(Enum(AssetType), nullable=False)
    pattern = Column(String(500), nullable=False)  # e.g., "*.example.com", "example.com", "https://app.example.com"
    allowed_methods = Column(String(500), default="GET,HEAD")
    notes = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    program = relationship("Program", back_populates="in_scope_assets")

    __table_args__ = (
        Index("idx_auth_asset_program_pattern", "program_id", "pattern"),
    )


class ExcludedAsset(Base):
    """Explicitly out-of-scope targets (never scanned)."""
    __tablename__ = "excluded_assets"

    id = Column(Integer, primary_key=True, index=True)
    program_id = Column(Integer, ForeignKey("programs.id", ondelete="CASCADE"), nullable=False)
    pattern = Column(String(500), nullable=False)  # e.g., "internal.example.com", "admin.example.com"
    reason = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    program = relationship("Program", back_populates="excluded_assets")

    __table_args__ = (
        Index("idx_excl_asset_program_pattern", "program_id", "pattern"),
    )


# -------------------------------------------------------------
# 3. Scan Jobs & Execution
# -------------------------------------------------------------
class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    program_id = Column(Integer, ForeignKey("programs.id", ondelete="CASCADE"), nullable=False)
    target = Column(String(500), nullable=False)
    mode = Column(Enum(ScanMode), default=ScanMode.PASSIVE, nullable=False)
    profile_name = Column(String(100), default="safe_default")
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    status_reason = Column(String(500), nullable=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    program = relationship("Program", back_populates="scan_jobs")
    events = relationship("ScanEvent", back_populates="job", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="job", cascade="all, delete-orphan")


class ScanEvent(Base):
    __tablename__ = "scan_events"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    event_type = Column(String(100), nullable=False)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    job = relationship("ScanJob", back_populates="events")


# -------------------------------------------------------------
# 4. Findings & Evidence
# -------------------------------------------------------------
class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    unique_finding_id = Column(String(64), unique=True, index=True, nullable=False)  # e.g. BB-2026-0001
    program_id = Column(Integer, ForeignKey("programs.id", ondelete="CASCADE"), nullable=False)
    job_id = Column(Integer, ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True)
    asset = Column(String(500), nullable=False)
    category = Column(String(150), nullable=False)  # e.g. Missing Security Header, Weak TLS, Exposed Config
    title = Column(String(300), nullable=False)
    description = Column(Text, nullable=False)
    evidence_summary = Column(Text, nullable=False)
    affected_component = Column(String(300), nullable=True)
    potential_impact = Column(Text, nullable=True)
    safe_reproduction = Column(Text, nullable=True)
    policy_reference = Column(String(500), nullable=True)
    recommended_remediation = Column(Text, nullable=True)
    detection_method = Column(String(100), default="safe_passive_check")

    severity = Column(Enum(FindingSeverity), default=FindingSeverity.INFO, nullable=False)
    confidence = Column(Enum(FindingConfidence), default=FindingConfidence.LOW, nullable=False)
    status = Column(Enum(FindingStatus), default=FindingStatus.DISCOVERED, nullable=False)

    deduplication_hash = Column(String(64), index=True, nullable=False)
    duplicate_of_id = Column(Integer, ForeignKey("findings.id", ondelete="SET NULL"), nullable=True)

    discovered_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    program = relationship("Program", back_populates="findings")
    job = relationship("ScanJob", back_populates="findings")
    evidence_items = relationship("FindingEvidence", back_populates="finding", cascade="all, delete-orphan")
    approvals = relationship("Approval", back_populates="finding", cascade="all, delete-orphan")


class FindingEvidence(Base):
    """Sanitized evidence items associated with a finding."""
    __tablename__ = "finding_evidence"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    evidence_type = Column(String(100), nullable=False)  # HTTP_HEADERS, TLS_METADATA, ADVISORY_MATCH
    raw_evidence = Column(Text, nullable=False)  # Sanitized, no credentials or PII
    created_at = Column(DateTime, default=datetime.utcnow)

    finding = relationship("Finding", back_populates="evidence_items")


# -------------------------------------------------------------
# 5. Human Approval Workflow
# -------------------------------------------------------------
class Approval(Base):
    """Explicit human approval request for active / Mode C tests."""
    __tablename__ = "approvals"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=True)
    target_asset = Column(String(500), nullable=False)
    proposed_test = Column(String(200), nullable=False)
    reason = Column(Text, nullable=False)
    expected_impact = Column(Text, nullable=False)
    rate_limit_rps = Column(Float, default=1.0)
    window_start = Column(DateTime, nullable=False)
    window_end = Column(DateTime, nullable=False)
    status = Column(Enum(ApprovalStatus), default=ApprovalStatus.PENDING, nullable=False)
    decision_reason = Column(String(500), nullable=True)
    decided_by = Column(String(100), nullable=True)
    decided_at = Column(DateTime, nullable=True)
    token = Column(String(128), unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    finding = relationship("Finding", back_populates="approvals")
    events = relationship("ApprovalEvent", back_populates="approval", cascade="all, delete-orphan")


class ApprovalEvent(Base):
    __tablename__ = "approval_events"

    id = Column(Integer, primary_key=True, index=True)
    approval_id = Column(Integer, ForeignKey("approvals.id", ondelete="CASCADE"), nullable=False)
    actor = Column(String(100), nullable=False)
    action = Column(String(100), nullable=False)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    approval = relationship("Approval", back_populates="events")


# -------------------------------------------------------------
# 6. Notifications & Deduplication
# -------------------------------------------------------------
class EmailNotification(Base):
    __tablename__ = "email_notifications"

    id = Column(Integer, primary_key=True, index=True)
    recipient = Column(String(255), nullable=False)
    subject = Column(String(500), nullable=False)
    notification_type = Column(String(100), nullable=False)
    deduplication_key = Column(String(128), index=True, nullable=False)
    status = Column(Enum(NotificationStatus), default=NotificationStatus.PENDING, nullable=False)
    body_text = Column(Text, nullable=False)
    error_message = Column(Text, nullable=True)
    attempts = Column(Integer, default=0)
    sent_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


# -------------------------------------------------------------
# 7. Immutable Security Audit Log
# -------------------------------------------------------------
class AuditLog(Base):
    """Immutable audit trail for authorization, scope decisions, and approvals."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    actor = Column(String(100), nullable=False)
    action = Column(String(100), nullable=False)  # SCOPE_CHECK, TARGET_REJECTED, SCAN_TRIGGERED, EMERGENCY_STOP
    target = Column(String(500), nullable=True)
    decision = Column(String(50), nullable=False)  # ALLOW, DENY, PASS, STOP
    reason = Column(Text, nullable=True)
    metadata_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


# -------------------------------------------------------------
# 8. Reports
# -------------------------------------------------------------
class VulnerabilityReport(Base):
    __tablename__ = "vulnerability_reports"

    id = Column(Integer, primary_key=True, index=True)
    program_id = Column(Integer, ForeignKey("programs.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(300), nullable=False)
    format = Column(String(20), default="MARKDOWN")  # MARKDOWN, HTML
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
