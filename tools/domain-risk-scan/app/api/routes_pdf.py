from datetime import datetime, timezone
from io import BytesIO
import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.scan import Scan
from app.services.report_service import build_report_payload, get_or_create_report

router = APIRouter(prefix="/api/pdf", tags=["pdf"])

LEFT = 50
RIGHT = 545
TOP = 800
BOTTOM = 60
LINE = 14
MAX_EVIDENCE_LIST_ITEMS = 6


def _get_scan_or_404(db: Session, scan_id: int) -> Scan:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def format_value(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)



def format_scan_timestamp(value: str | None) -> str:
    if not value:
        return "-"

    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return str(value)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone().strftime("%d/%m/%Y %H:%M")



def draw_wrapped_text(
    pdf: canvas.Canvas,
    text: str,
    x: int,
    y: int,
    max_width: int,
    font_name: str = "Helvetica",
    font_size: int = 10,
):
    pdf.setFont(font_name, font_size)
    words = str(text or "").split()
    if not words:
        return y - LINE

    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if stringWidth(candidate, font_name, font_size) <= max_width:
            current = candidate
        else:
            pdf.drawString(x, y, current)
            y -= LINE
            current = word

            if y < BOTTOM:
                pdf.showPage()
                y = TOP
                pdf.setFont(font_name, font_size)

    if current:
        pdf.drawString(x, y, current)
        y -= LINE

    return y



def ensure_space(pdf: canvas.Canvas, y: int, needed: int):
    if y < needed:
        pdf.showPage()
        return TOP
    return y



def draw_section_title(pdf: canvas.Canvas, title: str, y: int):
    y = ensure_space(pdf, y, 100)
    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(LEFT, y, title)
    return y - 20



def draw_kv(pdf: canvas.Canvas, label: str, value, y: int):
    y = ensure_space(pdf, y, 90)
    pdf.setFont("Helvetica-Bold", 10)
    pdf.drawString(LEFT, y, f"{label}:")
    pdf.setFont("Helvetica", 10)
    return draw_wrapped_text(pdf, format_value(value), LEFT + 95, y, RIGHT - (LEFT + 95))



def draw_bullets(pdf: canvas.Canvas, items: list[str], y: int):
    if not items:
        return draw_wrapped_text(pdf, "• No items available.", LEFT, y, RIGHT - LEFT)

    for item in items:
        y = ensure_space(pdf, y, 100)
        y = draw_wrapped_text(pdf, f"• {item}", LEFT, y, RIGHT - LEFT)
    return y



def draw_meta_line(pdf: canvas.Canvas, parts: list[str], y: int):
    cleaned = [part for part in parts if part]
    if not cleaned:
        return y
    return draw_wrapped_text(pdf, " | ".join(cleaned), LEFT + 10, y, RIGHT - LEFT - 10)



def draw_evidence_block(pdf: canvas.Canvas, evidence: dict, y: int):
    if not isinstance(evidence, dict) or not evidence:
        return y

    y = draw_wrapped_text(
        pdf,
        "Evidence:",
        LEFT + 10,
        y,
        RIGHT - LEFT - 10,
        font_name="Helvetica-Bold",
    )

    for key, value in evidence.items():
        if isinstance(value, list):
            preview = ", ".join(str(v) for v in value[:MAX_EVIDENCE_LIST_ITEMS])
            if len(value) > MAX_EVIDENCE_LIST_ITEMS:
                preview += ", ..."
            value_str = preview
        elif isinstance(value, dict):
            value_str = json.dumps(value, ensure_ascii=False)
        else:
            value_str = str(value)

        y = draw_wrapped_text(
            pdf,
            f"- {key}: {value_str}",
            LEFT + 20,
            y,
            RIGHT - LEFT - 20,
        )
    return y



def draw_finding(pdf: canvas.Canvas, finding: dict, y: int):
    y = ensure_space(pdf, y, 260)

    severity = str(finding.get("severity", "")).upper()
    category = finding.get("category", "")
    business_title = finding.get("business_title") or finding.get("title", "")
    technical_title = finding.get("technical_title") or finding.get("title", "")
    description = finding.get("description", "")
    business_impact = finding.get("business_impact")
    why_it_matters = finding.get("why_it_matters")
    recommendation = finding.get("recommendation")
    evidence = finding.get("evidence_json")

    # Accept both the old and the new enrichment field names to keep PDF rendering stable.
    remediation_steps = (
        finding.get("remediation_steps")
        or finding.get("steps")
        or []
    )
    technical_snippet = (
        finding.get("technical_snippet")
        or finding.get("copy_paste_snippet")
    )
    confidence_label = finding.get("confidence_label")
    remediation_complexity = (
        finding.get("remediation_complexity")
        or finding.get("effort")
        or finding.get("technical_complexity")
    )

    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawString(LEFT, y, f"[{severity}] {business_title}")
    y -= 16

    if technical_title:
        y = draw_wrapped_text(
            pdf,
            f"Technical finding: {technical_title}",
            LEFT + 10,
            y,
            RIGHT - LEFT - 10,
            font_name="Helvetica-Oblique",
        )

    y = draw_meta_line(
        pdf,
        [
            f"Category: {category}" if category else "",
            f"Confidence: {confidence_label}" if confidence_label else "",
            f"Complexity: {remediation_complexity}" if remediation_complexity else "",
        ],
        y,
    )

    if description:
        y = draw_wrapped_text(pdf, f"Description: {description}", LEFT + 10, y, RIGHT - LEFT - 10)

    if business_impact:
        y = draw_wrapped_text(
            pdf,
            "Business impact:",
            LEFT + 10,
            y,
            RIGHT - LEFT - 10,
            font_name="Helvetica-Bold",
        )
        y = draw_wrapped_text(pdf, business_impact, LEFT + 20, y, RIGHT - LEFT - 20)

    if why_it_matters:
        y = draw_wrapped_text(
            pdf,
            "Why it matters:",
            LEFT + 10,
            y,
            RIGHT - LEFT - 10,
            font_name="Helvetica-Bold",
        )
        y = draw_wrapped_text(pdf, why_it_matters, LEFT + 20, y, RIGHT - LEFT - 20)

    if recommendation:
        y = draw_wrapped_text(
            pdf,
            f"Recommendation: {recommendation}",
            LEFT + 10,
            y,
            RIGHT - LEFT - 10,
        )

    if remediation_steps:
        y = draw_wrapped_text(
            pdf,
            "Suggested steps:",
            LEFT + 10,
            y,
            RIGHT - LEFT - 10,
            font_name="Helvetica-Bold",
        )
        for step in remediation_steps:
            y = draw_wrapped_text(pdf, f"- {step}", LEFT + 20, y, RIGHT - LEFT - 20)

    if technical_snippet:
        y = draw_wrapped_text(
            pdf,
            "Technical snippet:",
            LEFT + 10,
            y,
            RIGHT - LEFT - 10,
            font_name="Helvetica-Bold",
        )
        y = draw_wrapped_text(
            pdf,
            technical_snippet,
            LEFT + 20,
            y,
            RIGHT - LEFT - 20,
            font_name="Courier",
            font_size=9,
        )

    y = draw_evidence_block(pdf, evidence, y)
    return y - 10


@router.get("/{scan_id}")
def export_pdf(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan_or_404(db, scan_id)

    if scan.status != "completed":
        raise HTTPException(
            status_code=409,
            detail=f"Scan {scan_id} is not ready yet. Current status: {scan.status}",
        )

    report = get_or_create_report(db, scan.id)
    if not report.is_paid:
        raise HTTPException(status_code=403, detail="Report not unlocked")

    payload = build_report_payload(db, scan, is_paid=True)

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    y = TOP

    # Header
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(LEFT, y, "Digital Risk Scanner")
    y -= 24

    pdf.setFont("Helvetica-Bold", 15)
    pdf.drawString(LEFT, y, f"Full Report - {payload['domain']}")
    y -= 26

    pdf.setFont("Helvetica", 10)
    pdf.drawString(LEFT, y, "External exposure snapshot based on DNS, TLS and passive subdomain signals.")
    y -= 24

    # Overview
    y = draw_section_title(pdf, "Risk Overview", y)
    y = draw_kv(pdf, "Domain", payload.get("domain"), y)
    y = draw_kv(pdf, "Score", f"{payload.get('score', '-')}/100", y)
    y = draw_kv(pdf, "Risk level", payload.get("risk_level"), y)
    y = draw_kv(pdf, "Top issue", payload.get("top_issue_title"), y)
    y = draw_kv(pdf, "Scan completed", format_scan_timestamp(payload.get("scan_completed_at")), y)
    y -= 8

    if payload.get("ai_top_risk_message"):
        y = draw_section_title(pdf, "Top Risk Message", y)
        y = draw_wrapped_text(pdf, payload["ai_top_risk_message"], LEFT, y, RIGHT - LEFT)
        y -= 8

    if payload.get("ai_teaser_summary"):
        y = draw_section_title(pdf, "Snapshot Summary", y)
        y = draw_wrapped_text(pdf, payload["ai_teaser_summary"], LEFT, y, RIGHT - LEFT)
        y -= 8

    # Severity breakdown
    y = draw_section_title(pdf, "Severity Breakdown", y)
    sev = payload.get("severity_breakdown") or {}
    y = draw_kv(pdf, "Critical", sev.get("critical", 0), y)
    y = draw_kv(pdf, "High", sev.get("high", 0), y)
    y = draw_kv(pdf, "Medium", sev.get("medium", 0), y)
    y = draw_kv(pdf, "Low", sev.get("low", 0), y)
    y -= 8

    # Executive summary
    if payload.get("ai_executive_summary"):
        y = draw_section_title(pdf, "Executive Summary", y)
        y = draw_wrapped_text(pdf, payload["ai_executive_summary"], LEFT, y, RIGHT - LEFT)
        y -= 8

    # What to fix first
    y = draw_section_title(pdf, "What to Fix First", y)
    y = draw_bullets(pdf, payload.get("priority_actions") or [], y)
    y -= 8

    # Key observations
    y = draw_section_title(pdf, "Key Observations", y)
    y = draw_bullets(pdf, payload.get("key_observations") or [], y)
    y -= 8

    # Action buckets
    y = draw_section_title(pdf, "Remediation Priorities", y)
    y = draw_wrapped_text(pdf, "Immediate actions:", LEFT, y, RIGHT - LEFT, font_name="Helvetica-Bold")
    y = draw_bullets(pdf, payload.get("immediate_actions") or [], y)
    y -= 6
    y = draw_wrapped_text(pdf, "Important improvements:", LEFT, y, RIGHT - LEFT, font_name="Helvetica-Bold")
    y = draw_bullets(pdf, payload.get("important_improvements") or [], y)
    y -= 6
    y = draw_wrapped_text(pdf, "Monitoring recommendations:", LEFT, y, RIGHT - LEFT, font_name="Helvetica-Bold")
    y = draw_bullets(pdf, payload.get("monitoring_recommendations") or [], y)
    y -= 8

    # Remediation plan
    if payload.get("ai_remediation_plan"):
        y = draw_section_title(pdf, "Remediation Plan", y)
        for line in str(payload["ai_remediation_plan"]).splitlines():
            if line.strip():
                y = draw_wrapped_text(pdf, line, LEFT, y, RIGHT - LEFT)
            else:
                y -= LINE
        y -= 8

    # Detailed findings
    y = draw_section_title(pdf, "Detailed Findings", y)
    findings = payload.get("findings") or []
    if not findings:
        y = draw_wrapped_text(pdf, "No findings available.", LEFT, y, RIGHT - LEFT)
    else:
        for finding in findings:
            y = draw_finding(pdf, finding, y)

    # Footer note
    y = ensure_space(pdf, y, 100)
    y -= 8
    pdf.setFont("Helvetica-Oblique", 9)
    pdf.drawString(
        LEFT,
        y,
        "This report is an automated external exposure snapshot and should be validated before remediation decisions.",
    )

    pdf.save()
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.pdf"},
    )
