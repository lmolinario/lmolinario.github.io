from __future__ import annotations
import json


def build_teaser_prompt(domain: str, score: int | None, findings: list[dict]) -> str:
    payload = {
        "domain": domain,
        "score": score,
        "findings": findings[:3],
    }

    return f"""
You are generating concise cybersecurity product copy for a domain risk scanner.

Rules:
- Do not invent findings.
- Use only the provided findings.
- Do not use alarmist language.
- Do not claim compromise.
- Keep the tone professional, concise, business-friendly.
- Return valid JSON only.

Return JSON with:
- top_risk_message
- teaser_summary
- upgrade_cta

Input:
{json.dumps(payload, ensure_ascii=False)}
""".strip()


def build_full_report_prompt(domain: str, score: int | None, findings: list[dict]) -> str:
    payload = {
        "domain": domain,
        "score": score,
        "findings": findings,
    }

    return f"""
You are generating explanatory cybersecurity report text for a domain risk scanner.

Rules:
- Do not invent findings.
- Use only the provided input.
- Do not use fear-based or sensational language.
- Avoid legal or absolute claims.
- Explain findings in plain but professional language.
- Return valid JSON only.

Return JSON with:
- executive_summary
- explained_findings: array of objects with
  - title
  - severity
  - what_it_means
  - why_it_matters
  - what_to_do_next
- remediation_plan: array of strings

Input:
{json.dumps(payload, ensure_ascii=False)}
""".strip()