from __future__ import annotations

from typing import Any

import httpx


CRT_SH_URL = "https://crt.sh/"


def _make_finding(
    *,
    title: str,
    severity: str,
    description: str,
    category: str = "subdomain",
    finding_type: str = "security",
    recommendation: str | None = None,
    evidence_json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "category": category,
        "title": title,
        "severity": severity,
        "description": description,
        "recommendation": recommendation or "",
        "finding_type": finding_type,
        "evidence_json": evidence_json or {},
    }


def scan_subdomains(domain: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    try:
        response = httpx.get(
            CRT_SH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=12.0,
            follow_redirects=True,
        )
        response.raise_for_status()

        data = response.json()
        if not isinstance(data, list):
            findings.append(
                _make_finding(
                    title="Passive subdomain enumeration returned unexpected response",
                    severity="info",
                    description=(
                        f"crt.sh returned an unexpected payload while enumerating "
                        f"subdomains for {domain}. This does not indicate a domain risk, "
                        f"but passive coverage is incomplete."
                    ),
                    finding_type="coverage",
                    recommendation=(
                        "Repeat the scan later or integrate an additional passive source "
                        "for subdomain enumeration."
                    ),
                    evidence_json={
                        "source": "crt.sh",
                        "domain_checked": domain,
                        "check_type": "passive_subdomain_unexpected_response",
                        "scan_quality": "partial",
                    },
                )
            )
            return findings

        names: set[str] = set()

        for entry in data:
            name_value = entry.get("name_value")
            if not name_value:
                continue

            for raw_name in str(name_value).splitlines():
                sub = raw_name.strip().lower().rstrip(".")
                if sub and "*" not in sub:
                    names.add(sub)

        # Nessun finding se l'enumerazione va bene:
        # è dato contestuale, non rischio.
        return findings

    except httpx.TimeoutException as exc:
        findings.append(
            _make_finding(
                title="Passive subdomain enumeration timed out",
                severity="info",
                description=(
                    f"The external source crt.sh did not respond in time while checking "
                    f"{domain}. This is not a confirmed security issue. Passive exposure "
                    f"coverage is incomplete for this scan."
                ),
                finding_type="coverage",
                recommendation="Repeat the scan later.",
                evidence_json={
                    "source": "crt.sh",
                    "domain_checked": domain,
                    "error": str(exc),
                    "check_type": "passive_subdomain_timeout",
                    "scan_quality": "partial",
                },
            )
        )
        return findings

    except httpx.HTTPError as exc:
        findings.append(
            _make_finding(
                title="Passive subdomain enumeration unavailable",
                severity="info",
                description=(
                    f"The external source crt.sh could not be queried for {domain} "
                    f"({exc.__class__.__name__}). This does not indicate a vulnerability, "
                    f"but passive coverage is incomplete."
                ),
                finding_type="coverage",
                recommendation=(
                    "Repeat the scan later or add a secondary passive enumeration source."
                ),
                evidence_json={
                    "source": "crt.sh",
                    "domain_checked": domain,
                    "error": str(exc),
                    "check_type": "passive_subdomain_http_error",
                    "scan_quality": "partial",
                },
            )
        )
        return findings

    except Exception as exc:
        findings.append(
            _make_finding(
                title="Passive subdomain enumeration interrupted",
                severity="info",
                description=(
                    f"An unexpected scanner-side error occurred during passive subdomain "
                    f"enumeration for {domain}: {exc.__class__.__name__}. "
                    f"This is not a confirmed security issue."
                ),
                finding_type="scanner",
                recommendation="Check scanner logs and repeat the scan.",
                evidence_json={
                    "source": "crt.sh",
                    "domain_checked": domain,
                    "error": str(exc),
                    "check_type": "passive_subdomain_scanner_error",
                    "scan_quality": "partial",
                },
            )
        )
        return findings