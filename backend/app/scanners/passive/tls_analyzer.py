"""TLS Configuration and Certificate Security Analyzer.

Performs non-invasive, safe inspection of TLS/SSL parameters:
- Certificate expiration and remaining validity window
- Self-signed or untrusted certificate chains
- Legacy protocol versions (TLS 1.0 / 1.1)
"""
import ssl
import socket
from datetime import datetime
from typing import List, Optional
from backend.app.db.models import FindingSeverity, FindingConfidence, ScanMode
from backend.app.reports.remediation_catalog import get_detailed_solution
from backend.app.scanners.base import BaseScanner, RawFindingCandidate
from backend.app.engine.scope_engine import ScopeVerificationResult


class TLSAnalyzerScanner(BaseScanner):
    name: str = "tls_configuration_analyzer"
    description: str = "Checks TLS certificate validity and configuration"
    allowed_mode: ScanMode = ScanMode.SAFE_CHECKS

    async def execute_scan(
        self,
        target: str,
        scope_verification: ScopeVerificationResult
    ) -> List[RawFindingCandidate]:
        findings: List[RawFindingCandidate] = []
        host = scope_verification.normalized_host
        port = 443

        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.timeout_seconds) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
        except ssl.SSLCertVerificationError as e:
            findings.append(RawFindingCandidate(
                category="TLS/SSL Misconfiguration",
                title="TLS Certificate Validation Failed",
                description=f"The certificate presented by {host} failed validation: {str(e)}.",
                evidence_summary=f"Certificate verification error on {host}:443: {str(e)}",
                raw_evidence=str(e),
                affected_component=f"{host}:{port}",
                potential_impact="Users may receive browser security warnings or be vulnerable to interception.",
                safe_reproduction=f"openssl s_client -connect {host}:{port} -servername {host}",
                policy_reference="CWE-295: Improper Certificate Validation",
                recommended_remediation=get_detailed_solution("TLS Configuration", "Self-Signed or Untrusted TLS Certificate", target),
                detection_method="safe_tls_check",
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.CONFIRMED
            ))
            return findings
        except Exception:
            # Host does not listen on 443 or TLS handshake timed out
            return []

        if not cert:
            return findings

        # Check Certificate Expiration
        not_after_str = cert.get("notAfter")
        if not_after_str:
            try:
                # Format: 'May 10 12:00:00 2026 GMT'
                expire_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                now = datetime.utcnow()
                if expire_date < now:
                    findings.append(RawFindingCandidate(
                        category="TLS/SSL Misconfiguration",
                        title="Expired TLS Certificate",
                        description=f"The TLS certificate for {host} expired on {expire_date.isoformat()}.",
                        evidence_summary=f"Certificate expired at {expire_date.isoformat()}",
                        raw_evidence=f"notAfter: {not_after_str}",
                        affected_component=f"{host}:{port}",
                        potential_impact="Causes severe browser warnings and prevents secure client communication.",
                        safe_reproduction=f"openssl s_client -connect {host}:{port} -servername {host}",
                        policy_reference="CWE-298: Impending or Occurred Expiration of Key",
                        recommended_remediation=get_detailed_solution("TLS Configuration", "Expired TLS Certificate", target),
                        detection_method="safe_tls_check",
                        severity=FindingSeverity.HIGH,
                        confidence=FindingConfidence.CONFIRMED
                    ))
                elif (expire_date - now).days <= 14:
                    findings.append(RawFindingCandidate(
                        category="TLS/SSL Maintenance",
                        title=f"TLS Certificate Expiring Soon ({(expire_date - now).days} days left)",
                        description=f"The TLS certificate for {host} will expire on {expire_date.isoformat()}.",
                        evidence_summary=f"Expiration date: {expire_date.isoformat()} ({(expire_date - now).days} days remaining)",
                        raw_evidence=f"notAfter: {not_after_str}",
                        affected_component=f"{host}:{port}",
                        potential_impact="Risk of service interruption if not renewed before expiration.",
                        safe_reproduction=f"openssl s_client -connect {host}:{port} -servername {host}",
                        policy_reference="CWE-298",
                        recommended_remediation=get_detailed_solution("TLS Configuration", "TLS Certificate Expiring Soon", target),
                        detection_method="safe_tls_check",
                        severity=FindingSeverity.INFO,
                        confidence=FindingConfidence.HIGH
                    ))
            except Exception:
                pass

        # Check Cipher and Protocol Version
        if version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
            findings.append(RawFindingCandidate(
                category="Cryptographic Weakness",
                title=f"Deprecated TLS Protocol Version Supported ({version})",
                description=f"The server negotiated {version}, which is deprecated and contains known cryptographic weaknesses.",
                evidence_summary=f"Negotiated protocol: {version}, Cipher: {cipher}",
                raw_evidence=f"Version: {version}, Cipher: {cipher}",
                affected_component=f"{host}:{port}",
                potential_impact="Attackers may exploit protocol design flaws (e.g., BEAST, POODLE) to decrypt traffic.",
                safe_reproduction=f"openssl s_client -connect {host}:{port} -tls1_1",
                policy_reference="NIST SP 800-52r2; CWE-326",
                recommended_remediation=get_detailed_solution("TLS Configuration", "Deprecated TLS Version Supported", target),
                detection_method="safe_tls_check",
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.CONFIRMED
            ))

        return findings
