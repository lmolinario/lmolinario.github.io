from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.report import Report
from app.models.scan import Scan
from app.models.finding import Finding
from app.services.finding_enrichment_service import enrich_finding

import re
def _normalize_action_text(text: str) -> str:
    s = (text or "").strip().lower()
    if not s:
        return ""

    s = s.rstrip(".")
    s = re.sub(r"\s+", " ", s)

    replacements = [
        ("check whether ", ""),
        ("verify that ", ""),
        ("confirm that ", ""),
        ("ensure that ", ""),
        ("public dns", "dns"),
        ("in public dns", "in dns"),
        ("correctly in public dns", "correctly in dns"),
    ]

    for old, new in replacements:
        s = s.replace(old, new)

    return s


def _dedupe_action_list(actions: list[str], limit: int | None = None) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()

    for action in actions:
        cleaned = (action or "").strip()
        if not cleaned:
            continue

        norm = _normalize_action_text(cleaned)
        if not norm or norm in seen:
            continue

        seen.add(norm)
        result.append(cleaned)

        if limit is not None and len(result) >= limit:
            break

    return result

def get_or_create_report(db: Session, scan_id: int) -> Report:
    report = db.query(Report).filter(Report.scan_id == scan_id).first()
    if report:
        return report

    report = Report(
        scan_id=scan_id,
        is_paid=False,
        stripe_payment_status="pending",
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def get_report_by_scan(db: Session, scan_id: int) -> Report | None:
    return db.query(Report).filter(Report.scan_id == scan_id).first()


def mark_report_paid(
    db: Session,
    stripe_session_id: str,
    payment_status: str = "paid",
) -> Report | None:
    report = (
        db.query(Report)
        .filter(Report.stripe_session_id == stripe_session_id)
        .first()
    )
    if not report:
        return None

    if report.is_paid:
        return report

    report.is_paid = True
    report.stripe_payment_status = payment_status
    report.unlocked_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(report)
    return report


def set_report_checkout_session(
    db: Session,
    report: Report,
    stripe_session_id: str,
) -> Report:
    report.stripe_session_id = stripe_session_id
    report.stripe_payment_status = "pending"
    db.commit()
    db.refresh(report)
    return report


def _severity_rank(severity: str | None) -> int:
    order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }
    return order.get((severity or "").lower(), 0)



def _score_to_risk_level(score: int | None) -> str:
    if score is None:
        return "Unknown"
    if score >= 85:
        return "Low"
    if score >= 70:
        return "Moderate"
    if score >= 40:
        return "High"
    return "Critical"



def _get_evidence_dict(f: Finding) -> dict:
    return f.evidence_json if isinstance(f.evidence_json, dict) else {}

def _is_subdomain_lookup_failed(f: Finding) -> bool:
    category = (f.category or "").lower()
    if category != "subdomain":
        return False

    title = (f.title or "").lower()
    evidence = _get_evidence_dict(f)
    check_type = (evidence.get("check_type") or "").lower()

    return (
        "failed" in title
        or "timeout" in title
        or check_type in {"subdomain_lookup_failed", "passive_lookup_failed"}
        or bool(evidence.get("error"))
    )

def _finding_business_priority(f: Finding) -> int:
    title = (f.title or "").lower()
    category = (f.category or "").lower()
    evidence = _get_evidence_dict(f)
    check_type = (evidence.get("check_type") or "").lower()

    score = 0
    score += _severity_rank(f.severity) * 100

    if category == "dns":
        score += 40

        if check_type in {"dmarc_missing", "dmarc_invalid"} or "dmarc" in title:
            score += 55
        if check_type == "dmarc_lookup_failed":
            score += 30

        if check_type == "spf_missing" or "spf record missing" in title:
            score += 45
        if check_type == "spf_lookup_failed":
            score += 20

        if check_type == "mx_missing" or "mx records missing" in title:
            score += 35
        if check_type == "mx_lookup_failed":
            score += 25

        if "does not resolve in dns" in title:
            score += 50

    if category in {"ssl", "tls"}:
        score += 60

    if category == "subdomain":
        score += 20
        count = evidence.get("count")
        if isinstance(count, int):
            if count >= 20:
                score += 30
            elif count >= 10:
                score += 20
            elif count >= 5:
                score += 10

    if (f.recommendation or "").strip():
        score += 10

    return score



def _ordered_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (_finding_business_priority(f), int(f.id)),
        reverse=True,
    )



def _top_finding(findings: list[Finding]) -> Finding | None:
    if not findings:
        return None
    return _ordered_findings(findings)[0]



def _build_severity_breakdown(findings: list[Finding]) -> dict:
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = (f.severity or "").lower()
        if sev in breakdown:
            breakdown[sev] += 1
    return breakdown



def _finding_theme(f: Finding) -> str:
    title = (f.title or "").lower()
    category = (f.category or "").lower()
    evidence = _get_evidence_dict(f)
    check_type = (evidence.get("check_type") or "").lower()
    resolver_status = (evidence.get("resolver_status") or "").lower()

    if category == "dns" and check_type in {"dmarc_missing", "dmarc_invalid"}:
        return "email spoofing protection is missing or incomplete"
    if category == "dns" and check_type == "dmarc_lookup_failed":
        if resolver_status == "timeout":
            return "DMARC validation could not complete because DNS timed out"
        if resolver_status == "no_nameservers":
            return "DMARC validation could not complete because authoritative DNS servers did not respond correctly"
        return "DMARC validation could not complete due to a DNS resolution issue"
    if category == "dns" and check_type == "spf_missing":
        return "email sender authorization is incomplete because no SPF record was found"
    if category == "dns" and check_type == "spf_lookup_failed":
        return "SPF validation could not complete due to a DNS lookup issue"
    if category == "dns" and check_type == "mx_missing":
        return "inbound business email may not be configured because no MX records were found"
    if category == "dns" and check_type == "mx_lookup_failed":
        return "inbound email routing could not be validated because MX lookup failed"
    if category == "dns" and "does not resolve in dns" in title:
        return "core DNS resolution appears broken for the domain"
    if category in {"ssl", "tls"}:
        return "secure web trust may be impaired because HTTPS/TLS validation failed"
    if category == "subdomain":
        if _is_subdomain_lookup_failed(f):
            return "passive subdomain visibility could not be fully confirmed"
        return "publicly visible subdomains may be expanding the external attack surface"
    return (f.description or "This issue increases external exposure.").strip()



def _build_priority_actions(findings: list[Finding]) -> list[str]:
    ordered = _ordered_findings(findings)
    raw_actions: list[str] = []

    for f in ordered:
        enriched = enrich_finding(f, f.scan.domain if hasattr(f, "scan") and f.scan else "")
        steps = enriched.get("steps") or []
        recommendation = (f.recommendation or "").strip()

        preferred = steps[0].strip() if steps else recommendation
        if preferred:
            raw_actions.append(preferred)

    return _dedupe_action_list(raw_actions, limit=3)



def _bucket_label_for_finding(f: Finding) -> str:
    severity = (f.severity or "").lower()
    title = (f.title or "").lower()
    category = (f.category or "").lower()
    evidence = _get_evidence_dict(f)
    check_type = (evidence.get("check_type") or "").lower()

    if "does not resolve in dns" in title:
        return "immediate"

    if severity in {"critical", "high"}:
        return "immediate"

    if category == "dns" and check_type in {
        "dmarc_missing",
        "dmarc_invalid",
        "spf_missing",
    }:
        return "immediate"

    if category == "dns" and check_type in {
        "spf_lookup_failed",
        "mx_missing",
        "mx_lookup_failed",
        "dmarc_lookup_failed",
    }:
        return "important"

    if category in {"ssl", "tls"}:
        return "important"

    if category == "subdomain":
        if _is_subdomain_lookup_failed(f):
            return "important"
        return "monitor"

    return "important"



def _action_text_for_bucket(f: Finding) -> str:
    enriched = enrich_finding(f, "")
    recommendation = (f.recommendation or "").strip()
    steps = enriched.get("steps") or []

    if steps:
        return steps[0].strip()
    if recommendation:
        return recommendation
    return (enriched.get("business_title") or f.title or "Review this issue").strip()


def _build_action_buckets(findings: list[Finding]) -> dict[str, list[str]]:
    ordered = _ordered_findings(findings)

    raw_buckets = {
        "immediate_actions": [],
        "important_improvements": [],
        "monitoring_recommendations": [],
    }

    for f in ordered:
        text = _action_text_for_bucket(f)
        if not text:
            continue

        bucket = _bucket_label_for_finding(f)

        if bucket == "immediate":
            raw_buckets["immediate_actions"].append(text)
        elif bucket == "monitor":
            raw_buckets["monitoring_recommendations"].append(text)
        else:
            raw_buckets["important_improvements"].append(text)

    return {
        "immediate_actions": _dedupe_action_list(raw_buckets["immediate_actions"], limit=3),
        "important_improvements": _dedupe_action_list(raw_buckets["important_improvements"], limit=3),
        "monitoring_recommendations": _dedupe_action_list(raw_buckets["monitoring_recommendations"], limit=3),
    }


def _build_key_observations(findings: list[Finding]) -> list[str]:
    observations: list[str] = []

    for f in _ordered_findings(findings):
        evidence = _get_evidence_dict(f)
        category = (f.category or "").lower()
        check_type = (evidence.get("check_type") or "").lower()
        resolver_status = evidence.get("resolver_status")

        if category == "dns" and check_type in {"dmarc_missing", "dmarc_invalid"}:
            observations.append("The domain does not currently expose a valid DMARC policy, which weakens protection against email spoofing.")
            continue

        if category == "dns" and check_type == "spf_missing":
            observations.append("No valid SPF record was identified, so sender authorization cannot be clearly verified by receiving mail systems.")
            continue

        if category == "dns" and check_type == "mx_missing":
            observations.append("No MX records were found, which may prevent or disrupt inbound business email delivery.")
            continue

        if category == "dns" and check_type in {"dmarc_lookup_failed", "spf_lookup_failed", "mx_lookup_failed"}:
            if resolver_status:
                observations.append(f"A DNS lookup problem was observed during validation ({resolver_status}), which reduces confidence in the affected email-related control.")
            else:
                observations.append("A DNS lookup problem prevented full validation of one or more email-related controls.")
            continue

        if category == "dns" and "does not resolve in dns" in (f.title or "").lower():
            observations.append("The domain did not resolve cleanly in public DNS during the scan, which can affect multiple downstream services.")
            continue

        if category in {"ssl", "tls"}:
            observations.append("HTTPS/TLS validation did not complete successfully, which may weaken user trust and secure connectivity.")
            continue

        if category == "subdomain":
            if _is_subdomain_lookup_failed(f):
                error = evidence.get("error")
                if error:
                    observations.append(
                        f"Passive subdomain discovery did not complete successfully ({error}), so external asset visibility may be incomplete."
                    )
                else:
                    observations.append(
                        "Passive subdomain discovery did not complete successfully, so external asset visibility may be incomplete."
                    )
            else:
                count = evidence.get("count")
                if isinstance(count, int):
                    observations.append(
                        f"{count} public subdomains were observed, suggesting a broader external attack surface that should be reviewed."
                    )
                else:
                    observations.append(
                        "Public subdomains were observed and should be reviewed for legacy, test, or unmanaged services."
                    )
            continue

        if f.description:
            observations.append(f.description)

    deduped: list[str] = []
    seen = set()
    for item in observations:
        norm = item.strip().lower()
        if not norm or norm in seen:
            continue
        seen.add(norm)
        deduped.append(item)

    return deduped[:5]



def _build_business_summary_bits(findings: list[Finding]) -> list[str]:
    bits: list[str] = []

    for f in _ordered_findings(findings):
        bits.append(_finding_theme(f))

    deduped: list[str] = []
    seen = set()
    for item in bits:
        norm = item.strip().lower()
        if not norm or norm in seen:
            continue
        seen.add(norm)
        deduped.append(item)

    return deduped[:3]



def _build_fallback_ai_messages(
    scan: Scan,
    findings: list[Finding],
    is_paid: bool,
    report: Report | None = None,
) -> dict:
    stored = report.full_report_json if report and isinstance(report.full_report_json, dict) else {}

    top = _top_finding(findings)
    findings_count = len(findings)
    score = scan.score
    risk_level = _score_to_risk_level(score)

    ai_top_risk_message = stored.get("ai_top_risk_message")
    if not ai_top_risk_message:
        if top:
            enriched_top = enrich_finding(top, scan.domain)
            ai_top_risk_message = (
                f"Highest-priority issue: {enriched_top.get('business_title', top.title)} "
                f"({(top.severity or 'unknown').upper()} severity)."
            )
        else:
            ai_top_risk_message = "No material external risk signals were detected in this scan."

    ai_teaser_summary = stored.get("ai_teaser_summary")
    if not ai_teaser_summary:
        if findings_count == 0:
            ai_teaser_summary = (
                f"{scan.domain} currently presents a low visible external risk profile based on the checks performed."
            )
        else:
            themes = _build_business_summary_bits(findings)
            first_theme = themes[0] if themes else "visible external weaknesses were identified"
            ai_teaser_summary = (
                f"{scan.domain} shows {findings_count} finding(s) and a security score of {score}/100 "
                f"({risk_level.lower()} risk). The main signal is that {first_theme}."
            )

    ai_executive_summary = stored.get("ai_executive_summary")
    if not ai_executive_summary and is_paid:
        if findings_count == 0:
            ai_executive_summary = (
                f"{scan.domain} did not show material external exposure issues in the checks performed. "
                "At this stage, the visible internet-facing posture appears relatively low risk, but continued monitoring is still advisable."
            )
        else:
            highest = top.severity.upper() if top and top.severity else "UNKNOWN"
            business_bits = _build_business_summary_bits(findings)
            action_buckets = _build_action_buckets(findings)
            top_title = enrich_finding(top, scan.domain).get("business_title", top.title) if top else None

            summary_parts = [
                f"{scan.domain} received a security score of {score}/100, which corresponds to a {risk_level.lower()} external risk profile.",
                f"The scan identified {findings_count} finding(s), with highest observed severity {highest}.",
            ]

            if top_title:
                summary_parts.append(
                    f"The issue that deserves attention first is {top_title}."
                )

            if business_bits:
                summary_parts.append(
                    "The main exposure themes observed were: " + "; ".join(business_bits) + "."
                )

            if action_buckets["immediate_actions"]:
                summary_parts.append(
                    "Immediate remediation should focus on the items that affect domain trust, email authenticity, and service reachability first."
                )
            elif action_buckets["important_improvements"]:
                summary_parts.append(
                    "The identified issues are actionable and should be addressed in a prioritized remediation cycle."
                )

            summary_parts.append(
                "This report should be treated as an operational snapshot of the most visible external weaknesses that a customer, partner, or attacker could observe."
            )

            ai_executive_summary = " ".join(summary_parts)

    ai_remediation_plan = stored.get("ai_remediation_plan")
    if not ai_remediation_plan and is_paid:
        action_buckets = _build_action_buckets(findings)
        sections = []

        if action_buckets["immediate_actions"]:
            sections.append(
                "Immediate actions:\n"
                + "\n".join(f"- {a}" for a in action_buckets["immediate_actions"])
            )

        if action_buckets["important_improvements"]:
            sections.append(
                "Important improvements:\n"
                + "\n".join(f"- {a}" for a in action_buckets["important_improvements"])
            )

        if action_buckets["monitoring_recommendations"]:
            sections.append(
                "Monitoring recommendations:\n"
                + "\n".join(f"- {a}" for a in action_buckets["monitoring_recommendations"])
            )

        if sections:
            ai_remediation_plan = "\n\n".join(sections)
        else:
            ai_remediation_plan = (
                "Recommended actions:\n"
                "- Review the identified findings.\n"
                "- Prioritize the highest-severity and most business-relevant exposures first.\n"
                "- Re-run the scan after remediation to confirm closure."
            )

    return {
        "ai_top_risk_message": ai_top_risk_message,
        "ai_teaser_summary": ai_teaser_summary,
        "ai_executive_summary": ai_executive_summary if is_paid else None,
        "ai_remediation_plan": ai_remediation_plan if is_paid else None,
    }



def _build_findings_payload(findings: list[Finding], is_paid: bool, domain: str) -> list[dict]:
    ordered = _ordered_findings(findings)

    if is_paid:
        return [enrich_finding(f, domain) for f in ordered]

    enriched = [enrich_finding(f, domain) for f in ordered[:3]]

    teaser_payload = []
    for item in enriched:
        teaser_payload.append(
            {
                "id": item["id"],
                "category": item["category"],
                "severity": item["severity"],
                "title": item["business_title"],
                "technical_title": item["technical_title"],
                "description": item["description"],
                "business_impact": item["business_impact"],
            }
        )

    return teaser_payload



def build_report_payload(db: Session, scan: Scan, is_paid: bool) -> dict:
    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id)
        .order_by(Finding.id.asc())
        .all()
    )

    report = get_report_by_scan(db, scan.id)
    top = _top_finding(findings)
    top_enriched = enrich_finding(top, scan.domain) if top else None
    severity_breakdown = _build_severity_breakdown(findings)
    priority_actions = _build_priority_actions(findings)
    key_observations = _build_key_observations(findings)
    findings_payload = _build_findings_payload(findings, is_paid, scan.domain)
    action_buckets = _build_action_buckets(findings)

    ai_payload = _build_fallback_ai_messages(
        scan=scan,
        findings=findings,
        is_paid=is_paid,
        report=report,
    )

    return {
        "scan_id": scan.id,
        "domain": scan.domain,
        "score": scan.score,
        "is_paid": is_paid,
        "is_locked": not is_paid,
        "summary": scan.summary_json,
        "risk_level": _score_to_risk_level(scan.score),
        "severity_breakdown": severity_breakdown,
        "top_issue_title": top_enriched.get("business_title") if top_enriched else None,
        "priority_actions": priority_actions,
        "immediate_actions": action_buckets["immediate_actions"],
        "important_improvements": action_buckets["important_improvements"],
        "monitoring_recommendations": action_buckets["monitoring_recommendations"],
        "key_observations": key_observations,
        "scan_completed_at": scan.updated_at.isoformat() if scan.updated_at else None,
        "ai_top_risk_message": ai_payload["ai_top_risk_message"],
        "ai_teaser_summary": ai_payload["ai_teaser_summary"],
        "ai_executive_summary": ai_payload["ai_executive_summary"],
        "ai_remediation_plan": ai_payload["ai_remediation_plan"],
        "findings": findings_payload,
        "pdf_url": f"/api/pdf/{scan.id}" if is_paid else None,
    }



def persist_report_payload(db: Session, report: Report, scan: Scan) -> Report:
    payload = build_report_payload(db=db, scan=scan, is_paid=report.is_paid)

    existing = report.full_report_json if isinstance(report.full_report_json, dict) else {}

    snapshot = {
        **existing,
        "scan_id": payload["scan_id"],
        "domain": payload["domain"],
        "score": payload["score"],
        "summary": payload["summary"],
        "risk_level": payload["risk_level"],
        "severity_breakdown": payload["severity_breakdown"],
        "top_issue_title": payload["top_issue_title"],
        "priority_actions": payload["priority_actions"],
        "immediate_actions": payload["immediate_actions"],
        "important_improvements": payload["important_improvements"],
        "monitoring_recommendations": payload["monitoring_recommendations"],
        "key_observations": payload["key_observations"],
        "scan_completed_at": payload["scan_completed_at"],
        "ai_top_risk_message": payload["ai_top_risk_message"],
        "ai_teaser_summary": payload["ai_teaser_summary"],
        "findings_preview": payload["findings"] if not report.is_paid else existing.get("findings_preview"),
    }

    if report.is_paid:
        snapshot.update(
            {
                "ai_executive_summary": payload["ai_executive_summary"],
                "ai_remediation_plan": payload["ai_remediation_plan"],
                "findings_full": payload["findings"],
                "pdf_url": payload["pdf_url"],
                "paid_snapshot_at": datetime.now(timezone.utc).isoformat(),
            }
        )

    report.full_report_json = snapshot
    db.commit()
    db.refresh(report)
    return report
