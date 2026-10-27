"""API Endpoints for Generating and Downloading Vulnerability Reports in TXT, DOCX, and MD."""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from backend.app.db.base import get_db
from backend.app.db.models import VulnerabilityReport, Finding
from backend.app.reports.generator import (
    create_and_save_report,
    generate_finding_docx_report,
    generate_finding_text_report,
    generate_finding_markdown_report,
    generate_full_audit_docx_report,
    generate_full_audit_text_report,
    generate_docx_from_markdown
)

router = APIRouter()


@router.get("")
def list_reports(db: Session = Depends(get_db)):
    return db.query(VulnerabilityReport).order_by(VulnerabilityReport.created_at.desc()).all()


@router.post("/generate/{finding_id}")
def generate_report(finding_id: int, db: Session = Depends(get_db)):
    try:
        report = create_and_save_report(db, finding_id)
        return report
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/finding/{finding_id}/export")
def export_finding_report(finding_id: int, format: str = "docx", author: Optional[str] = None, db: Session = Depends(get_db)):
    """Export a specific finding report as .docx, .txt, or .md."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    fmt = format.lower().strip()
    safe_title = "".join(c for c in finding.title if c.isalnum() or c in ("-", "_")).rstrip()[:40]

    if fmt == "docx":
        docx_bytes = generate_finding_docx_report(db, finding, author=author)
        filename = f"report_{finding.unique_finding_id}_{safe_title}.docx"
        return Response(
            content=docx_bytes,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    elif fmt == "txt":
        txt_content = generate_finding_text_report(db, finding, author=author)
        filename = f"report_{finding.unique_finding_id}_{safe_title}.txt"
        return Response(
            content=txt_content,
            media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    else:  # default to markdown
        md_content = generate_finding_markdown_report(db, finding, author=author)
        filename = f"report_{finding.unique_finding_id}_{safe_title}.md"
        return Response(
            content=md_content,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )


@router.get("/export-all")
def export_all_findings_report(program_id: Optional[int] = None, format: str = "docx", author: Optional[str] = None, db: Session = Depends(get_db)):
    """Export a comprehensive audit report of all findings as .docx or .txt."""
    fmt = format.lower().strip()
    prefix = f"program_{program_id}" if program_id else "full_audit"

    if fmt == "docx":
        docx_bytes = generate_full_audit_docx_report(db, program_id, author=author)
        filename = f"{prefix}_security_report.docx"
        return Response(
            content=docx_bytes,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    else:
        txt_content = generate_full_audit_text_report(db, program_id, author=author)
        filename = f"{prefix}_security_report.txt"
        return Response(
            content=txt_content,
            media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )


@router.get("/{report_id}/download")
def download_report(report_id: int, format: str = "md", author: Optional[str] = None, db: Session = Depends(get_db)):
    report = db.query(VulnerabilityReport).filter(VulnerabilityReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    fmt = format.lower().strip()
    safe_title = "".join(c for c in report.title if c.isalnum() or c in ("-", "_")).rstrip()[:40]

    if fmt == "docx":
        docx_bytes = generate_docx_from_markdown(report.content, title=report.title, author=author)
        return Response(
            content=docx_bytes,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f'attachment; filename="report_{report.id}_{safe_title}.docx"'}
        )
    elif fmt == "txt":
        return Response(
            content=report.content,
            media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="report_{report.id}_{safe_title}.txt"'}
        )
    else:
        return Response(
            content=report.content,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="report_{report.id}_{safe_title}.md"'}
        )
