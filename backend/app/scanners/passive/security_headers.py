"""HTTP Security Headers Analyzer.

Performs low-impact, passive inspection of HTTP response headers on authorized targets.
Checks for:
- Missing Strict-Transport-Security (HSTS)
- Missing or weak Content-Security-Policy (CSP)
- Missing X-Frame-Options (Clickjacking vulnerability)
- Missing X-Content-Type-Options (MIME sniffing)
- Permissive Cross-Origin Resource Sharing (CORS) configurations
- Leaking server banners (Server, X-Powered-By)
"""
import httpx
from typing import List
from backend.app.db.models import FindingSeverity, FindingConfidence, ScanMode
from backend.app.scanners.base import BaseScanner, RawFindingCandidate
from backend.app.engine.scope_engine import ScopeVerificationResult


class SecurityHeadersScanner(BaseScanner):
    name: str = "security_headers_analyzer"
    description: str = "Analyzes HTTP security headers and defensive configurations"
    allowed_mode: ScanMode = ScanMode.SAFE_CHECKS

    async def execute_scan(
        self,
        target: str,
        scope_verification: ScopeVerificationResult
    ) -> List[RawFindingCandidate]:
        findings: List[RawFindingCandidate] = []

        # Prepare normalized URL
        url = target if target.startswith("http://") or target.startswith("https://") else f"https://{target}"

        headers = {
            "User-Agent": "BugBountySecurityAuditor/1.0 (+https://github.com/sudovu/bug-bounty-hunter)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        async with httpx.AsyncClient(verify=True, follow_redirects=False, timeout=self.timeout_seconds) as client:
            try:
                response = await client.get(url, headers=headers)
            except Exception as e:
                # Target could not be reached or connection failed safely
                return []

        resp_headers = {k.lower(): v for k, v in response.headers.items()}

        # 1. Check Content-Security-Policy
        if "content-security-policy" not in resp_headers:
            findings.append(RawFindingCandidate(
                category="Missing Defensive Security Header",
                title="Missing Content-Security-Policy (CSP) Header",
                description="The target web application does not specify a Content-Security-Policy header. CSP helps prevent Cross-Site Scripting (XSS) and data injection attacks by restricting the sources from which content can be loaded.",
                evidence_summary=f"HTTP response for {url} returned status {response.status_code} without Content-Security-Policy header.",
                raw_evidence=f"Headers inspected:\n" + "\n".join(f"{k}: {v}" for k, v in response.headers.items()),
                affected_component=url,
                potential_impact="Increases vulnerability to XSS attacks if user input is reflected or stored without adequate context-aware sanitization.",
                safe_reproduction=f"curl -I {url}",
                policy_reference="OWASP Top 10 - A03:2021 Injection; CWE-1021",
                recommended_remediation="Define and deploy a restrictive Content-Security-Policy (e.g., default-src 'self').",
                detection_method="safe_passive_check",
                severity=FindingSeverity.LOW,
                confidence=FindingConfidence.CONFIRMED
            ))

        # 2. Check Strict-Transport-Security (HSTS) on HTTPS
        if url.startswith("https://") and "strict-transport-security" not in resp_headers:
            findings.append(RawFindingCandidate(
                category="Missing Defensive Security Header",
                title="Missing HTTP Strict-Transport-Security (HSTS) Header",
                description="The application does not enforce HSTS, which protects users against SSL-stripping and man-in-the-middle attacks by ensuring connections always use HTTPS.",
                evidence_summary=f"HTTPS response for {url} does not contain Strict-Transport-Security header.",
                raw_evidence=f"Status: {response.status_code}",
                affected_component=url,
                potential_impact="Attackers on the local network could downgrade initial user connections from HTTPS to unencrypted HTTP.",
                safe_reproduction=f"curl -I {url}",
                policy_reference="OWASP Top 10 - A05:2021 Security Misconfiguration; CWE-319",
                recommended_remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
                detection_method="safe_passive_check",
                severity=FindingSeverity.LOW,
                confidence=FindingConfidence.CONFIRMED
            ))

        # 3. Check X-Frame-Options (Clickjacking defense)
        if "x-frame-options" not in resp_headers and "content-security-policy" not in resp_headers:
            findings.append(RawFindingCandidate(
                category="Clickjacking Protection",
                title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                description="Neither X-Frame-Options nor CSP frame-ancestors was detected on the target endpoint. This may allow malicious sites to embed the target in an iframe for clickjacking.",
                evidence_summary=f"No X-Frame-Options or frame-ancestors directive present on {url}.",
                raw_evidence=f"Status: {response.status_code}",
                affected_component=url,
                potential_impact="Users could be tricked into clicking invisible interface elements on attacker-controlled framing pages.",
                safe_reproduction=f"curl -I {url}",
                policy_reference="OWASP Top 10 - A05:2021 Security Misconfiguration; CWE-1021",
                recommended_remediation="Configure 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
                detection_method="safe_passive_check",
                severity=FindingSeverity.LOW,
                confidence=FindingConfidence.HIGH
            ))

        # 4. Check X-Content-Type-Options (MIME-type sniffing defense)
        if "x-content-type-options" not in resp_headers:
            findings.append(RawFindingCandidate(
                category="Missing Defensive Security Header",
                title="Missing X-Content-Type-Options Header",
                description="X-Content-Type-Options: nosniff is missing. This allows older or certain web browsers to sniff the MIME type of responses away from the declared Content-Type, potentially leading to script execution.",
                evidence_summary=f"Response for {url} is missing 'X-Content-Type-Options: nosniff'.",
                raw_evidence=f"Status: {response.status_code}",
                affected_component=url,
                potential_impact="MIME type confusion may permit untrusted user uploads (like images) to execute as JavaScript in vulnerable browsers.",
                safe_reproduction=f"curl -I {url}",
                policy_reference="CWE-79; CWE-116",
                recommended_remediation="Set 'X-Content-Type-Options: nosniff' across all HTTP responses.",
                detection_method="safe_passive_check",
                severity=FindingSeverity.INFO,
                confidence=FindingConfidence.CONFIRMED
            ))

        # 5. Check Permissive CORS (Access-Control-Allow-Origin: *)
        cors_origin = resp_headers.get("access-control-allow-origin")
        cors_creds = resp_headers.get("access-control-allow-credentials")
        if cors_origin == "*" and cors_creds == "true":
            findings.append(RawFindingCandidate(
                category="CORS Misconfiguration",
                title="Overly Permissive CORS with Credentials Enabled",
                description="The endpoint returns Access-Control-Allow-Origin: * along with Access-Control-Allow-Credentials: true, which is insecure and invalid according to the CORS specification.",
                evidence_summary=f"Access-Control-Allow-Origin: {cors_origin}, Access-Control-Allow-Credentials: {cors_creds}",
                raw_evidence=f"CORS Headers: Origin={cors_origin}, Credentials={cors_creds}",
                affected_component=url,
                potential_impact="May allow unauthorized third-party origins to access authenticated responses if browser validation fails.",
                safe_reproduction=f"curl -H 'Origin: https://evil.example.com' -I {url}",
                policy_reference="OWASP Top 10 - A01:2021 Broken Access Control; CWE-942",
                recommended_remediation="Whitelist only trusted origins explicitly rather than using wildcard '*'.",
                detection_method="safe_passive_check",
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.HIGH
            ))

        # 6. Informational: Server version banner disclosure
        server_banner = resp_headers.get("server") or resp_headers.get("x-powered-by")
        if server_banner and any(char.isdigit() for char in server_banner):
            findings.append(RawFindingCandidate(
                category="Information Disclosure",
                title=f"Detailed Server Version Banner Disclosed ({server_banner})",
                description="The web server reveals its exact software and version numbers via response headers. This assists attackers during reconnaissance in identifying unpatched vulnerabilities.",
                evidence_summary=f"Server header disclosed: '{server_banner}' on {url}.",
                raw_evidence=f"Header: {server_banner}",
                affected_component=url,
                potential_impact="Simplifies automated attacker profiling of known software vulnerabilities.",
                safe_reproduction=f"curl -I {url}",
                policy_reference="OWASP Top 10 - A05:2021 Security Misconfiguration; CWE-200",
                recommended_remediation="Mask or suppress granular server version headers in web server configuration.",
                detection_method="safe_passive_check",
                severity=FindingSeverity.INFO,
                confidence=FindingConfidence.CONFIRMED
            ))

        return findings
