"""Unit Tests for Scanners and Finding Generation."""
import pytest
from unittest.mock import patch, AsyncMock
import httpx

from backend.app.scanners.passive.security_headers import SecurityHeadersScanner
from backend.app.scanners.passive.secret_scanner import SecretScanner
from backend.app.engine.scope_engine import ScopeVerificationResult
from backend.app.db.models import FindingSeverity


@pytest.mark.asyncio
async def test_security_headers_missing_csp():
    scanner = SecurityHeadersScanner(timeout_seconds=5)
    
    mock_resp = httpx.Response(
        status_code=200,
        headers={"Server": "nginx/1.18.0", "Content-Type": "text/html"},
        request=httpx.Request("GET", "https://api.acme.example.com")
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp

        scope_res = ScopeVerificationResult(
            allowed=True,
            decision="ALLOW",
            reason="In scope",
            target="api.acme.example.com",
            normalized_host="api.acme.example.com",
            program_id=1
        )
        findings = await scanner.execute_scan("api.acme.example.com", scope_res)
        
        titles = [f.title for f in findings]
        assert "Missing Content-Security-Policy (CSP) Header" in titles
        assert "Missing HTTP Strict-Transport-Security (HSTS) Header" in titles
        assert "Detailed Server Version Banner Disclosed (nginx/1.18.0)" in titles


def test_secret_scanner_local_content():
    scanner = SecretScanner()
    
    content = """
    # Configuration file
    AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
    GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    """
    findings = scanner.scan_content("config.py", content)
    assert len(findings) == 2
    categories = [f.category for f in findings]
    assert all(c == "Exposed Credential / Secret" for c in categories)
