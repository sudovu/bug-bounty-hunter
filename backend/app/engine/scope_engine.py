"""Scope and Authorization Engine.

The central security gatekeeper of the Bug Bounty Hunter Bot.
Enforces:
- Strict destination resolution & anti-SSRF checks
- Program authorization validity and expiration dates
- Explicit exclusions (exclusions ALWAYS override inclusions)
- Conservative wildcard & domain matching
- CIDR network block matching
- URL path containment
- Default-to-DENY policy
- Audit logging for every evaluation
"""
import ipaddress
import re
from datetime import datetime
from typing import Optional, List, Tuple
from urllib.parse import urlparse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.core.emergency import emergency_control
from backend.app.core.ssrf_protection import validate_destination_safety, extract_host
from backend.app.core.audit import record_audit_event
from backend.app.db.models import (
    Program, AuthorizedAsset, ExcludedAsset, AssetType, ScanMode
)


class ScopeVerificationResult(BaseModel):
    allowed: bool
    decision: str  # ALLOW or DENY
    reason: str
    target: str
    normalized_host: str
    program_id: int
    matched_asset_id: Optional[int] = None
    rate_limit_rps: float = 1.0


def normalize_hostname(target: str) -> str:
    """Extract and normalize hostname in lower case."""
    return extract_host(target).lower().rstrip('.')


def match_domain_pattern(host: str, pattern: str) -> bool:
    """Matches host against a domain or wildcard pattern conservatively.
    
    Examples:
    - pattern: 'example.com', host: 'example.com' -> True
    - pattern: '*.example.com', host: 'sub.example.com' -> True
    - pattern: '*.example.com', host: 'a.b.example.com' -> True
    - pattern: '*.example.com', host: 'example.com' -> False (unless explicitly scoped)
    - pattern: '*.example.com', host: 'attacker-example.com' -> False
    """
    pattern = pattern.strip().lower().rstrip('.')
    host = host.strip().lower().rstrip('.')

    if pattern == host:
        return True

    if pattern.startswith("*."):
        root_domain = pattern[2:]
        if host.endswith("." + root_domain):
            return True
        return False

    return False


def match_cidr_pattern(ip_str: str, cidr_pattern: str) -> bool:
    """Check if an IP falls within a CIDR pattern."""
    try:
        ip = ipaddress.ip_address(ip_str)
        net = ipaddress.ip_network(cidr_pattern, strict=False)
        return ip in net
    except Exception:
        return False


def match_url_pattern(target_url: str, pattern_url: str) -> bool:
    """Check if target_url starts with pattern_url path and matches scheme/host."""
    target_parsed = urlparse(target_url)
    pattern_parsed = urlparse(pattern_url)

    if pattern_parsed.scheme and target_parsed.scheme != pattern_parsed.scheme:
        return False
    if (target_parsed.hostname or "").lower() != (pattern_parsed.hostname or "").lower():
        return False

    # Path check: target path must start with pattern path
    pattern_path = pattern_parsed.path.rstrip('/')
    target_path = target_parsed.path.rstrip('/')
    if not pattern_path:
        return True
    return target_path == pattern_path or target_path.startswith(pattern_path + '/')


def is_target_excluded(target: str, host: str, exclusions: List[ExcludedAsset]) -> Tuple[bool, Optional[str]]:
    """Check if target or host matches any explicitly excluded asset."""
    for exclusion in exclusions:
        excl_pattern = exclusion.pattern.strip().lower()
        # Direct string equality
        if excl_pattern == host or excl_pattern == target.lower():
            return True, f"Target matches excluded pattern '{exclusion.pattern}' (Reason: {exclusion.reason or 'Unspecified'})"
        # Wildcard exclusion
        if excl_pattern.startswith("*."):
            if match_domain_pattern(host, excl_pattern):
                return True, f"Target matches excluded wildcard pattern '{exclusion.pattern}'"
        # CIDR exclusion
        if "/" in excl_pattern:
            if match_cidr_pattern(host, excl_pattern):
                return True, f"Target IP matches excluded CIDR '{exclusion.pattern}'"
    return False, None


def is_target_in_scope(target: str, host: str, assets: List[AuthorizedAsset]) -> Tuple[bool, Optional[AuthorizedAsset], str]:
    """Check if target or host matches an authorized in-scope asset."""
    for asset in assets:
        pat = asset.pattern.strip()
        asset_type = asset.asset_type

        if asset_type == AssetType.WILDCARD or pat.startswith("*."):
            if match_domain_pattern(host, pat):
                return True, asset, f"Matched in-scope wildcard '{pat}'"
        elif asset_type == AssetType.DOMAIN:
            if match_domain_pattern(host, pat):
                return True, asset, f"Matched in-scope domain '{pat}'"
        elif asset_type == AssetType.URL:
            if match_url_pattern(target, pat):
                return True, asset, f"Matched in-scope URL '{pat}'"
        elif asset_type == AssetType.CIDR:
            if match_cidr_pattern(host, pat):
                return True, asset, f"Matched in-scope CIDR '{pat}'"
        elif asset_type == AssetType.REPOSITORY:
            if pat.lower() in target.lower():
                return True, asset, f"Matched in-scope repository '{pat}'"

    return False, None, "Target does not match any authorized in-scope asset"


def verify_target_authorization(
    db: Session,
    program_id: int,
    target: str,
    requested_mode: ScanMode = ScanMode.PASSIVE,
    actor: str = "system"
) -> ScopeVerificationResult:
    """Mandatory verification routine before any scan or network connection.
    
    Enforces:
    1. Global emergency stop status
    2. Program paused status
    3. Program existence and active authorization
    4. Authorization expiration check
    5. Anti-SSRF / Cloud metadata / Private IP blocking
    6. Program exclusions (Exclusions ALWAYS win)
    7. Program in-scope allowlist matching
    8. Immutable audit logging
    """
    host = normalize_hostname(target)

    # 1. Check Global Emergency Stop
    if emergency_control.is_global_stopped():
        reason = "Operation rejected: Global emergency stop is ACTIVE."
        record_audit_event(db, actor=actor, action="SCOPE_CHECK", decision="DENY", target=target, reason=reason)
        return ScopeVerificationResult(
            allowed=False, decision="DENY", reason=reason, target=target,
            normalized_host=host, program_id=program_id
        )

    # 2. Check Per-Program Pause
    if emergency_control.is_program_paused(program_id):
        reason = f"Operation rejected: Program {program_id} is currently PAUSED."
        record_audit_event(db, actor=actor, action="SCOPE_CHECK", decision="DENY", target=target, reason=reason)
        return ScopeVerificationResult(
            allowed=False, decision="DENY", reason=reason, target=target,
            normalized_host=host, program_id=program_id
        )

    # 3. Retrieve Program
    program = db.query(Program).filter(Program.id == program_id).first()
    if not program:
        reason = f"Program ID {program_id} not found in database."
        record_audit_event(db, actor=actor, action="SCOPE_CHECK", decision="DENY", target=target, reason=reason)
        return ScopeVerificationResult(
            allowed=False, decision="DENY", reason=reason, target=target,
            normalized_host=host, program_id=program_id
        )

    # 4. Check Authorization Active Flag
    if not program.authorization_active:
        reason = f"Program '{program.name}' authorization is inactive or disabled."
        record_audit_event(db, actor=actor, action="SCOPE_CHECK", decision="DENY", target=target, reason=reason)
        return ScopeVerificationResult(
            allowed=False, decision="DENY", reason=reason, target=target,
            normalized_host=host, program_id=program_id
        )

    # 5. Check Authorization Expiry Date
    if program.authorization_expires_at and program.authorization_expires_at < datetime.utcnow():
        reason = f"Program '{program.name}' authorization expired on {program.authorization_expires_at.isoformat()}."
        record_audit_event(db, actor=actor, action="SCOPE_CHECK", decision="DENY", target=target, reason=reason)
        return ScopeVerificationResult(
            allowed=False, decision="DENY", reason=reason, target=target,
            normalized_host=host, program_id=program_id
        )

    # 6. Strict SSRF and Destination Safety Check
    is_safe, ssrf_reason, resolved_ips = validate_destination_safety(target)
    if not is_safe:
        reason = f"Security block (Anti-SSRF): {ssrf_reason}"
        record_audit_event(
            db, actor=actor, action="SSRF_BLOCK", decision="DENY", target=target,
            reason=reason, metadata={"resolved_ips": resolved_ips}
        )
        return ScopeVerificationResult(
            allowed=False, decision="DENY", reason=reason, target=target,
            normalized_host=host, program_id=program_id
        )

    # 7. Check Exclusions (Exclusions ALWAYS override allowlist)
    excluded, excl_reason = is_target_excluded(target, host, program.excluded_assets)
    if excluded:
        reason = f"Explicitly excluded from scope: {excl_reason}"
        record_audit_event(db, actor=actor, action="SCOPE_EXCLUSION_BLOCK", decision="DENY", target=target, reason=reason)
        return ScopeVerificationResult(
            allowed=False, decision="DENY", reason=reason, target=target,
            normalized_host=host, program_id=program_id
        )

    # 8. Check In-Scope Allowlist
    in_scope, matched_asset, match_reason = is_target_in_scope(target, host, program.in_scope_assets)
    if not in_scope:
        reason = f"Target '{target}' is not in authorized scope allowlist."
        record_audit_event(db, actor=actor, action="OUT_OF_SCOPE_BLOCK", decision="DENY", target=target, reason=reason)
        return ScopeVerificationResult(
            allowed=False, decision="DENY", reason=reason, target=target,
            normalized_host=host, program_id=program_id
        )

    # 9. Target is fully verified and authorized
    audit_meta = {
        "matched_asset_id": matched_asset.id if matched_asset else None,
        "pattern": matched_asset.pattern if matched_asset else None,
        "mode": requested_mode.value,
        "resolved_ips": resolved_ips
    }
    record_audit_event(
        db, actor=actor, action="SCOPE_VERIFIED", decision="ALLOW", target=target,
        reason=f"Target verified in-scope under program '{program.name}'", metadata=audit_meta
    )

    return ScopeVerificationResult(
        allowed=True,
        decision="ALLOW",
        reason=match_reason,
        target=target,
        normalized_host=host,
        program_id=program.id,
        matched_asset_id=matched_asset.id if matched_asset else None,
        rate_limit_rps=program.max_rate_limit or 1.0
    )
