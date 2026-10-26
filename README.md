# Bug Bounty Hunter Bot 🛡️

An ethical, automated **Bug Bounty Discovery & Vulnerability Management Bot** designed to operate strictly on authorized assets within published bug bounty program scopes.

Built with **FastAPI**, **SQLAlchemy**, and a modern cybersecurity dashboard, featuring:
- **Central Scope & Authorization Engine:** Strict allowlist evaluation, exclusion overrides, wildcard subdomain resolution, anti-SSRF protections, and default-to-DENY policy.
- **Safety Modes:**
  - **Mode A (Passive Discovery):** Non-invasive metadata, public policies, and static file inspection.
  - **Mode B (Safe Automated Checks):** Low-impact defensive security header analysis and TLS/certificate verification.
  - **Mode C (Approval Required):** Explicit human authorization workflow before any active or intrusive validation.
  - **Mode D (Manual Review Only):** Guard against exploits, credential attacks, or denial-of-service.
- **Email Alert Service:** Automated SMTP notifications with deduplication, retry, and credential/secret redaction.
- **Interactive Security Dashboard:** Live scope verification dry-run, finding triage, human approval queues, audit trails, and formal Markdown report export.
- **Global Emergency Stop:** Instant kill-switch to immediately abort all scanner requests.

---

## 🏗️ Architecture

```
bug_bounty_hunter/
├── backend/
│   └── app/
│       ├── api/v1/          # REST API endpoints (programs, scans, findings, approvals, system, reports)
│       ├── core/            # Config, Anti-SSRF guard, Audit logging, Emergency stop
│       ├── db/              # SQLAlchemy models & database session
│       ├── engine/          # Scope & Authorization Engine, Human Approval Engine
│       ├── notifications/   # SMTP email service, templates, deduplication
│       ├── reports/         # Vulnerability report generators (Markdown/HTML)
│       ├── scanners/        # Base scanner, Security headers analyzer, TLS analyzer, Orchestrator
│       ├── schemas/         # Pydantic request/response schemas
│       ├── static/          # Embedded cybersecurity web dashboard
│       └── main.py          # FastAPI application entrypoint
├── tests/                   # Automated Pytest suite (22 tests covering scope, SSRF, approvals, email)
├── .env.example             # Configuration template
├── Dockerfile               # Container build specification
├── docker-compose.yml       # Production deployment compose
└── requirements.txt         # Python dependencies
```

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+ (Tested up to Python 3.14)
- Git

### 2. Local Setup

Clone the repository and set up a virtual environment:

```bash
git clone https://github.com/sudovu/bug-bounty-hunter.git
cd bug_bounty_hunter

python -m venv .venv
# On Windows:
.\.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Configure Environment Variables

Copy the template:
```bash
cp .env.example .env
```

Edit `.env` to configure your SMTP credentials for email alerts:
```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_FROM_EMAIL=scanner-alerts@yourdomain.com
ALERT_TO_EMAIL=bounty-researcher@yourdomain.com
EMAIL_NOTIFICATIONS_ENABLED=true
```

### 4. Start the Application

```bash
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

Open your browser to access:
- **Interactive Dashboard:** [http://localhost:8000](http://localhost:8000)
- **API Documentation (Swagger UI):** [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 🔒 Security & Scope Safeguards

### Anti-SSRF Destination Guard
Every destination hostname or URL is resolved and checked against:
- Loopback addresses (`127.0.0.0/8`, `::1`)
- RFC 1918 Private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Cloud Metadata Services (`169.254.169.254`, `metadata.google.internal`)
- Carrier-Grade NAT (`100.64.0.0/10`)
- Link-local and documentation ranges

### Default-to-DENY Policy
A target is rejected unless it explicitly matches an approved in-scope pattern and is NOT in the program's exclusion list.

---

## 🧪 Running the Test Suite

Run all automated unit and integration tests:

```bash
pytest -v
```

The test suite covers:
- In-scope target acceptance & out-of-scope rejection
- Subdomain wildcards & exclusion overrides
- Expired program authorization blocking
- SSRF and cloud metadata endpoint interception
- Human approval token validation and time window expiration
- Email deduplication and secret redaction
- Safe header and TLS scanning
- Global emergency stop kill-switch

---

## 🐳 Docker Deployment

Run with Docker Compose:

```bash
docker compose up -d
```

The service will run on port `8000` with persistent database storage in `./data/`.
