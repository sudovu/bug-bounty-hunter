import ipaddress
import socket
from datetime import datetime
from urllib.parse import urlparse
from typing import Tuple, List, Optional
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.core.emergency import emergency_control
from backend.app.core.audit import record_audit_event
from backend.app.core.ssrf_protection import validate_destination_safety, extract_host
from backend.app.db.models import (
    Program, AuthorizedAsset, ExcludedAsset, AssetType, ScanMode
)


class ScopeVerificationResult(BaseModel):
    allowed: bool
    decision: str  # ALLOW, DENY, REQUIRE_APPROVAL
    reason: str
    target: str
    normalized_host: str
    program_id: Optional[int] = None
    matched_asset_id: Optional[int] = None
    required_mode: Optional[str] = None


def match_domain_pattern(host: str, pattern: str) -> bool:
    """Evaluate if a host matches a domain or wildcard pattern.
    
    Supports standard bug bounty conventions:
    - pattern: 'example.com', host: 'example.com' -> True
    - pattern: 'example.com', host: 'www.example.com' -> True
    - pattern: '*.example.com', host: 'example.com' -> True (apex domain included in scope)
    - pattern: '*.example.com', host: 'sub.example.com' -> True
    - pattern: '*.example.com', host: 'a.b.example.com' -> True
    - pattern: '*.example.com', host: 'attacker-example.com' -> False
    """
    pattern = pattern.strip().lower().rstrip('.')
    host = host.strip().lower().rstrip('.')

    if pattern == host:
        return True

    if pattern.startswith("*."):
        root_domain = pattern[2:]
        if host == root_domain or host.endswith("." + root_domain):
            return True
        return False

    # A domain scope 'example.com' also covers its subdomains 'sub.example.com'
    if host.endswith("." + pattern):
        return True

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
    requested_mode: ScanMode = ScanMode.SAFE_CHECKS,
    actor: str = "system"
) -> ScopeVerificationResult:
    """Central Scope & Authorization Gatekeeper.
    
    Enforces the central security invariant:
    No scanner network request is ever performed on an asset that is not strictly authorized.
    
    Verification Flow:
    1. Validate input format and extract host
    2. Check Global Emergency Stop (Immediate hard abort)
    3. Retrieve Program and check active authorization & expiry date
    4. Check Anti-SSRF destination safety (Prohibit private, loopback, and metadata IPs)
    5. Check Scope Exclusions (Exclusions override allowlist unconditionally)
    6. Check In-Scope Allowlist
    7. Enforce Safety Mode constraints (Mode C requires human approval, Mode D is manual review only)
    8. Record tamper-evident audit trail log
    """
    target = target.strip()
    host = extract_host(target)

    # 1. Basic sanity
    if not target or not host:
        reason = "Invalid target or empty host provided."
        record_audit_event(db, actor=actor, action="SCOPE_CHECK", decision="DENY", target=target, reason=reason)
        return ScopeVerificationResult(
            allowed=False, decision="DENY", reason=reason, target=target,
            normalized_host=host or "", program_id=program_id
        )

    # 2. Check Global Emergency Stop
    if emergency_control.is_global_stopped():
        reason = "Operation rejected: Global Emergency Stop is active."
        record_audit_event(db, actor=actor, action="EMERGENCY_STOP_BLOCK", decision="DENY", target=target, reason=reason)
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
    in_scope, matched_asset, scope_reason = is_target_in_scope(target, host, program.in_scope_assets)
    if not in_scope:
        reason = f"Target '{target}' is not in authorized scope allowlist."
        record_audit_event(db, actor=actor, action="OUT_OF_SCOPE_BLOCK", decision="DENY", target=target, reason=reason)
        return ScopeVerificationResult(
            allowed=False, decision="DENY", reason=reason, target=target,
            normalized_host=host, program_id=program_id
        )

    # 9. Safety Mode Assessment
    if requested_mode == ScanMode.MANUAL_REVIEW:
        reason = "Mode D: Target requires manual human review. Automated execution prohibited."
        record_audit_event(db, actor=actor, action="MODE_D_REVIEW_REQUIRED", decision="DENY", target=target, reason=reason)
        return ScopeVerificationResult(
            allowed=False, decision="REQUIRE_MANUAL_REVIEW", reason=reason,
            target=target, normalized_host=host, program_id=program_id,
            matched_asset_id=matched_asset.id if matched_asset else None,
            required_mode="MANUAL_REVIEW"
        )

    if requested_mode == ScanMode.APPROVAL_REQUIRED:
        reason = "Mode C: Action requires explicit human approval before execution."
        record_audit_event(db, actor=actor, action="MODE_C_APPROVAL_REQUIRED", decision="REQUIRE_APPROVAL", target=target, reason=reason)
        return ScopeVerificationResult(
            allowed=False, decision="REQUIRE_APPROVAL", reason=reason,
            target=target, normalized_host=host, program_id=program_id,
            matched_asset_id=matched_asset.id if matched_asset else None,
            required_mode="APPROVAL_REQUIRED"
        )

    # 10. Authorization Granted
    success_reason = f"Target verified in-scope under program '{program.name}'. {scope_reason}."
    record_audit_event(
        db, actor=actor, action="SCOPE_VERIFIED", decision="ALLOW",
        target=target, reason=success_reason,
        metadata={"program_id": program.id, "asset_id": matched_asset.id if matched_asset else None}
    )

    return ScopeVerificationResult(
        allowed=True,
        decision="ALLOW",
        reason=success_reason,
        target=target,
        normalized_host=host,
        program_id=program.id,
        matched_asset_id=matched_asset.id if matched_asset else None,
        required_mode=requested_mode.value
    )
