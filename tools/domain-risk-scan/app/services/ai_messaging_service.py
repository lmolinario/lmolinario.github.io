from __future__ import annotations

from typing import Any


def generate_fallback_teaser_message(score: int | None, findings: list[dict[str, Any]]) -> dict[str, Any]:
    if not findings:
        return {
            "top_risk_message": "No major exposure signals were identified in the current scan preview.",
            "teaser_summary": "A limited number of external checks were completed. Unlock the full report for a structured explanation and remediation guidance.",
        }

    top = findings[0]
    severity = str(top.get("severity", "")).lower()
    title = top.get("title", "an exposure signal")

    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "moderate",
        "low": "limited",
    }

    risk_word = severity_map.get(severity, "notable")

    return {
        "top_risk_message": f"The main issue detected is {title.lower()}, which may indicate {risk_word} external exposure.",
        "teaser_summary": "Unlock the full report to see what this means, why it matters, and which actions should be prioritized.",
    }


def generate_fallback_full_messages(domain: str, score: int | None, findings: list[dict[str, Any]]) -> dict[str, Any]:
    executive_summary = (
        f"The scan for {domain} identified {len(findings)} findings. "
        f"The current score indicates a measurable level of external exposure. "
        f"The most important next step is to review the highest-severity findings first."
    )

    explained_findings = []
    for f in findings:
        title = f.get("title", "Unknown issue")
        description = f.get("description", "")
        severity = f.get("severity", "unknown")

        explained_findings.append(
            {
                "title": title,
                "severity": severity,
                "what_it_means": description or "This finding indicates a domain configuration or exposure signal that should be reviewed.",
                "why_it_matters": "This issue may increase risk, reduce trust, or weaken the domain’s external security posture.",
                "what_to_do_next": "Review the affected configuration and apply remediation according to your DNS, email, or web infrastructure setup.",
            }
        )

    remediation_plan = [
        "Review the highest-severity findings first.",
        "Prioritize controls affecting email trust, TLS posture, and public exposure.",
        "Re-run the scan after remediation to confirm the updated posture.",
    ]

    return {
        "executive_summary": executive_summary,
        "explained_findings": explained_findings,
        "remediation_plan": remediation_plan,
    }