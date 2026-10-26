"""Static Secret Detection Scanner.

Detects accidentally exposed tokens, credentials, or keys in source files or text.
Never exposes or uses discovered credentials.
"""
import re
from typing import List, Dict
from backend.app.db.models import FindingSeverity, FindingConfidence, ScanMode
from backend.app.scanners.base import BaseScanner, RawFindingCandidate
from backend.app.engine.scope_engine import ScopeVerificationResult

SECRET_RULES = [
    {
        "id": "AWS_KEY",
        "name": "AWS Access Key ID",
        "regex": r"(?i)\b(AKIA[0-9A-Z]{16})\b",
        "severity": FindingSeverity.HIGH,
        "remediation": "Revoke the exposed key in AWS IAM immediately."
    },
    {
        "id": "GITHUB_PAT",
        "name": "GitHub Personal Access Token",
        "regex": r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b",
        "severity": FindingSeverity.HIGH,
        "remediation": "Revoke the GitHub token and remove from git history using git-filter-repo."
    },
    {
        "id": "SLACK_TOKEN",
        "name": "Slack Bot/User Token",
        "regex": r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b",
        "severity": FindingSeverity.HIGH,
        "remediation": "Revoke the Slack OAuth token in your Slack API dashboard."
    },
    {
        "id": "RSA_PRIVATE_KEY",
        "name": "Unencrypted Private Key",
        "regex": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        "severity": FindingSeverity.CRITICAL,
        "remediation": "Rotate compromised private keys and replace with securely stored secrets."
    }
]


class SecretScanner(BaseScanner):
    name: str = "static_secret_scanner"
    description: str = "Scans source files or configuration for hardcoded secrets"
    allowed_mode: ScanMode = ScanMode.SAFE_CHECKS

    def scan_content(self, filename: str, content: str) -> List[RawFindingCandidate]:
        """Inspect text content for known secret signatures."""
        findings = []
        for rule in SECRET_RULES:
            matches = list(re.finditer(rule["regex"], content))
            if matches:
                findings.append(RawFindingCandidate(
                    category="Exposed Credential / Secret",
                    title=f"Potential Hardcoded Secret Discovered: {rule['name']}",
                    description=f"Static pattern matching detected a potential {rule['name']} in '{filename}'.",
                    evidence_summary=f"Discovered pattern matching {rule['name']} in file {filename} (count: {len(matches)}).",
                    raw_evidence=f"File: {filename}, Rule: {rule['name']} (Secret values are redacted for security).",
                    affected_component=filename,
                    potential_impact="Unauthorized third-party access to cloud infrastructure, code repositories, or APIs.",
                    safe_reproduction=f"Inspect line in {filename}",
                    policy_reference="CWE-798: Use of Hard-coded Credentials",
                    recommended_remediation=rule["remediation"],
                    detection_method="static_secret_analysis",
                    severity=rule["severity"],
                    confidence=FindingConfidence.HIGH
                ))
        return findings

    async def execute_scan(
        self,
        target: str,
        scope_verification: ScopeVerificationResult
    ) -> List[RawFindingCandidate]:
        # For remote target endpoints, static secret scanner does not run over network
        return []
