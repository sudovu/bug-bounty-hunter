"""Comprehensive Security Remediation Catalog.

Provides detailed, actionable, multi-step remediation guidance,
including web server configuration directives (Nginx, Apache, Cloudflare),
verification steps, and industry standards.
"""
from typing import Dict, Any, Optional


CSP_DETAILED_SOLUTION = """1. Executive Remediation Strategy:
Deploy a strict Content-Security-Policy (CSP) HTTP header to instruct modern browsers on which dynamic resources are permitted to load, completely stopping unauthorized inline scripts, eval(), and external cross-site scripting (XSS) vectors.

2. Web Server Configuration Directives:
• Nginx (/etc/nginx/sites-available/default):
  add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;

• Apache HTTP Server (.htaccess or httpd.conf):
  <IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
  </IfModule>

• Cloudflare / Edge CDN:
  Configure a Transform Rule -> Modify Response Header -> Set Static:
  Header Name: Content-Security-Policy
  Value: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none';

• Node.js (Express Framework):
  const helmet = require('helmet');
  app.use(helmet.contentSecurityPolicy());

3. Phased Rollout Recommendation:
Before enforcing, deploy Content-Security-Policy-Report-Only with a report-uri or report-to endpoint to monitor for false positives without breaking legitimate scripts.

4. Safe Verification Command:
curl -s -I {asset} | grep -i content-security-policy"""


HSTS_DETAILED_SOLUTION = """1. Executive Remediation Strategy:
Enforce HTTP Strict Transport Security (HSTS) on all HTTPS endpoints to instruct browsers to interact only over encrypted HTTPS, mitigating SSL-stripping, protocol downgrade, and cookie hijacking attacks.

2. Web Server Configuration Directives:
• Nginx (/etc/nginx/nginx.conf or server block):
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

• Apache HTTP Server:
  <IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
  </IfModule>

• Cloudflare / Edge Reverse Proxy:
  Navigate to SSL/TLS -> Edge Certificates -> Enable "HTTP Strict Transport Security (HSTS)"
  Set Max-Age: 12 months (31,536,000 seconds)
  Include Subdomains: Enabled
  Preload: Enabled

3. Safe Verification Command:
curl -s -I -L {asset} | grep -i strict-transport-security"""


CLICKJACKING_DETAILED_SOLUTION = """1. Executive Remediation Strategy:
Prevent user interface redressing (Clickjacking) attacks by instructing user-agents never to render your application inside an <iframe>, <frame>, <embed>, or <object> on unauthorized external domains.

2. Web Server Configuration Directives:
• Nginx:
  add_header X-Frame-Options "SAMEORIGIN" always;

• Apache:
  <IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
  </IfModule>

• Modern Content-Security-Policy Alternative:
  add_header Content-Security-Policy "frame-ancestors 'self';" always;

3. Safe Verification Command:
curl -s -I {asset} | grep -E -i "x-frame-options|frame-ancestors\""""


NOSNIFF_DETAILED_SOLUTION = """1. Executive Remediation Strategy:
Prevent MIME-confusion and drive-by download attacks by instructing web browsers to strictly adhere to the Content-Type header and never sniff responses into executable MIME types.

2. Web Server Configuration Directives:
• Nginx:
  add_header X-Content-Type-Options "nosniff" always;

• Apache:
  <IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
  </IfModule>

• Microsoft IIS (web.config):
  <httpProtocol>
    <customHeaders>
      <add name="X-Content-Type-Options" value="nosniff" />
    </customHeaders>
  </httpProtocol>

3. Safe Verification Command:
curl -s -I {asset} | grep -i x-content-type-options"""


CORS_DETAILED_SOLUTION = """1. Executive Remediation Strategy:
Correct Cross-Origin Resource Sharing (CORS) misconfigurations. When credentials (cookies, Authorization tokens) are transmitted, never echo wildcard '*' in Access-Control-Allow-Origin.

2. Remediation Directives & Logic:
• Maintain an explicit server-side allowlist of trusted origins (e.g., https://*.ewnet.com.np, https://portal.ewnet.com.np).
• Dynamically compare the incoming HTTP Origin header against the allowlist.
• If and only if the Origin matches the trusted allowlist, reflect that specific Origin in Access-Control-Allow-Origin.
• Set Access-Control-Allow-Credentials: true only for authorized allowlisted origins.

3. Safe Verification Command:
curl -s -I -H "Origin: https://unauthorized-attacker.com" {asset} | grep -i access-control"""


SERVER_BANNER_DETAILED_SOLUTION = """1. Executive Remediation Strategy:
Suppress granular software version numbers in HTTP Server and X-Powered-By banners to prevent automated profiling and reconnaissance of known CVEs.

2. Server Configuration Directives:
• Nginx (/etc/nginx/nginx.conf):
  server_tokens off;

• Apache (/etc/apache2/conf-available/security.conf):
  ServerTokens Prod
  ServerSignature Off

• PHP (php.ini):
  expose_php = Off

• Node.js / Express:
  app.disable('x-powered-by');

3. Safe Verification Command:
curl -s -I {asset} | grep -E -i "server:|x-powered-by" """


TLS_DETAILED_SOLUTION = """1. Executive Remediation Strategy:
Harden Transport Layer Security (TLS) configuration by disabling outdated cipher suites, terminating legacy protocols (TLS 1.0, TLS 1.1), and enforcing trusted, automatically renewing X.509 certificates.

2. Server Configuration Directives:
• Enforce TLS 1.2 and TLS 1.3:
  Nginx: ssl_protocols TLSv1.2 TLSv1.3;
  Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3

• Modern Cipher Suite Selection:
  ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
  ssl_prefer_server_ciphers on;

• Automated Certificate Lifecycle (Let's Encrypt / Certbot):
  certbot --nginx -d ewnet.com.np -d www.ewnet.com.np --redirect
  certbot renew --dry-run

3. Safe Verification Command:
openssl s_client -connect {asset_host}:443 -tls1_2 < /dev/null"""


SECRET_DETAILED_SOLUTION = """1. Executive Incident Response & Remediation:
Step 1: Immediate Token Invalidation:
Revoke the exposed key/token immediately in the issuing service console (AWS IAM, GitHub Tokens, Stripe Dashboard, etc.) to terminate unauthorized access windows.

Step 2: Credential Rotation:
Generate a new high-entropy secret and distribute it exclusively via secure environment secrets or vault management systems (HashiCorp Vault, AWS Secrets Manager, GitHub Secrets).

Step 3: History & Log Scrubbing:
If committed to version control, use tools like git-filter-repo or BFG Repo-Cleaner to rewrite history and scrub secret traces.

Step 4: Audit Access Logs:
Review provider authentication logs during the exposure timeframe to verify whether unauthorized API calls were made."""


def get_detailed_solution(category: str, title: str, asset: str, fallback: Optional[str] = None) -> str:
    """Returns a rich, detailed, multi-step technical remediation plan."""
    cat_lower = (category or "").lower()
    tit_lower = (title or "").lower()
    asset_clean = asset.strip() if asset else "https://ewnet.com.np"
    asset_host = asset_clean.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    if "content-security-policy" in tit_lower or "csp" in tit_lower:
        return CSP_DETAILED_SOLUTION.format(asset=asset_clean)
    elif "strict-transport-security" in tit_lower or "hsts" in tit_lower:
        return HSTS_DETAILED_SOLUTION.format(asset=asset_clean)
    elif "frame" in tit_lower or "clickjacking" in tit_lower or "x-frame-options" in tit_lower:
        return CLICKJACKING_DETAILED_SOLUTION.format(asset=asset_clean)
    elif "content-type-options" in tit_lower or "nosniff" in tit_lower:
        return NOSNIFF_DETAILED_SOLUTION.format(asset=asset_clean)
    elif "cors" in tit_lower or "cross-origin" in tit_lower:
        return CORS_DETAILED_SOLUTION.format(asset=asset_clean)
    elif "banner" in tit_lower or "server" in tit_lower or "version" in tit_lower or "information disclosure" in cat_lower:
        return SERVER_BANNER_DETAILED_SOLUTION.format(asset=asset_clean)
    elif "tls" in cat_lower or "tls" in tit_lower or "certificate" in tit_lower or "ssl" in tit_lower:
        return TLS_DETAILED_SOLUTION.format(asset_clean=asset_clean, asset_host=asset_host)
    elif "secret" in cat_lower or "key" in tit_lower or "token" in tit_lower or "credential" in tit_lower:
        return SECRET_DETAILED_SOLUTION

    # If fallback is provided and detailed enough (> 150 chars), return it
    if fallback and len(fallback.strip()) > 150:
        return fallback

    # Default structured technical remediation
    base = fallback or "Implement standard defensive security controls and vendor hardening recommendations."
    return f"""1. Immediate Technical Remediation:
{base}

2. Recommended Implementation Steps:
• Review server configuration files and web application gateway settings.
• Test changes in staging before applying to production.
• Confirm non-breaking operation with legitimate user workflows.

3. Safe Verification Command:
curl -s -I {asset_clean}"""
