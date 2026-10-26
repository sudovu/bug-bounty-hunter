"""Vulnerability and Scope Report Generator.

Creates professional, evidence-backed security reports in Markdown and HTML.
Suitable for responsible disclosure submissions to authorized bug bounty programs.
"""
from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session
from backend.app.db.models import Finding, Program, VulnerabilityReport


def generate_finding_markdown_report(db: Session, finding: Finding) -> str:
    program = db.query(Program).filter(Program.id == finding.program_id).first()
    program_name = program.name if program else "Authorized Security Program"
    program_url = program.program_url if program else "N/A"

    evidence_text = finding.evidence_summary
    if finding.evidence_items:
        evidence_text += "\n\n### Supporting Evidence Items:\n"
        for item in finding.evidence_items:
            evidence_text += f"- **Type:** `{item.evidence_type}`\n```\n{item.raw_evidence}\n```\n"

    report_md = f"""# VULNERABILITY REPORT: {finding.title}

---
**Report ID:** `{finding.unique_finding_id}`  
**Program:** [{program_name}]({program_url})  
**Target Asset:** `{finding.asset}`  
**Severity:** **{finding.severity.value}**  
**Confidence:** {finding.confidence.value}  
**Status:** {finding.status.value}  
**Date Discovered:** {finding.discovered_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Detection Method:** `{finding.detection_method}`  
---

## 1. Executive Summary
During authorized security assessment on `{finding.asset}`, a security weakness categorized under **{finding.category}** was identified.
This finding has been assessed with **{finding.severity.value}** severity based on non-invasive technical evidence.

## 2. Technical Description
{finding.description}

- **Affected Component:** `{finding.affected_component or finding.asset}`
- **Security Standard / Policy Reference:** {finding.policy_reference or 'Responsible Disclosure Best Practices'}

## 3. Evidence & Verification
{evidence_text}

## 4. Potential Security Impact
{finding.potential_impact or 'Detailed impact depends on surrounding defensive architecture.'}

## 5. Safe Steps to Reproduce
The following non-destructive verification steps can safely confirm the reported behavior:

```bash
{finding.safe_reproduction or '# Safe curl check'}
```

> **Notice:** All testing was conducted strictly within authorized scope in compliance with the program policy. No exploits, payloads, or intrusive actions were performed.

## 6. Remediation Recommendations
{finding.recommended_remediation or 'Apply vendor patches and follow modern defensive configuration standards.'}

---
*Report generated automatically by Bug Bounty Hunter Bot.*
"""
    return report_md


def create_and_save_report(db: Session, finding_id: int) -> VulnerabilityReport:
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise ValueError(f"Finding {finding_id} not found")

    content = generate_finding_markdown_report(db, finding)
    report = VulnerabilityReport(
        program_id=finding.program_id,
        title=f"Report: {finding.title} ({finding.unique_finding_id})",
        format="MARKDOWN",
        content=content,
        created_at=datetime.utcnow()
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report
