from __future__ import annotations

from typing import Any

from app.models.finding import Finding



def _normalize_domain(domain: str) -> str:
    return (domain or "").strip().lower()



def _get_evidence_dict(f: Finding) -> dict[str, Any]:
    return f.evidence_json if isinstance(f.evidence_json, dict) else {}



def _resolver_suffix(status: str) -> str:
    mapping = {
        "timeout": "because DNS queries timed out",
        "no_nameservers": "because authoritative name servers did not return usable responses",
        "nxdomain": "because the domain did not resolve in public DNS",
        "no_answer": "because DNS returned no usable answer",
    }
    return mapping.get(status, "due to a DNS resolution issue")



def _default_finding_payload(f: Finding, domain: str) -> dict[str, Any]:
    return {
        "id": f.id,
        "category": f.category,
        "severity": f.severity,
        "title": f.title,
        "technical_title": f.title,
        "business_title": f.title,
        "description": f.description,
        "business_impact": "This issue may increase visible external exposure and should be reviewed.",
        "why_it_matters": "Issues left unresolved can weaken trust, service reliability, or the domain's external security posture.",
        "evidence_json": f.evidence_json,
        "recommendation": f.recommendation,
        "effort": "Medium",
        "technical_complexity": "Medium",
        "steps": [
            "Review the affected configuration.",
            "Apply the recommended change.",
            "Run the scan again to confirm the issue is resolved.",
        ],
        "copy_paste_snippet": None,
    }



def _enrich_dmarc_missing(f: Finding, domain: str) -> dict[str, Any]:
    mailbox = f"security@{_normalize_domain(domain)}" if domain else "security@example.com"

    payload = _default_finding_payload(f, domain)
    payload.update({
        "business_title": "Email spoofing protection is missing or incomplete",
        "business_impact": (
            "Attackers may be able to impersonate your domain in phishing or fraudulent email campaigns. "
            "That can damage brand trust, expose customers to scams, and reduce confidence in legitimate messages."
        ),
        "why_it_matters": (
            "Without a valid DMARC policy, receiving mail systems have no clear instruction for how to handle spoofed messages that claim to come from your domain."
        ),
        "effort": "Low (< 15 minutes)",
        "technical_complexity": "Low",
        "steps": [
            "Open the DNS management panel for the domain.",
            "Create or update the TXT record at _dmarc.",
            "Start with a monitoring policy such as p=none if you need a low-risk first step.",
            "Add reporting addresses so DMARC results can be reviewed.",
            "Wait for propagation and re-run the scan.",
        ],
        "copy_paste_snippet": f"v=DMARC1; p=none; rua=mailto:{mailbox}; ruf=mailto:{mailbox}; fo=1;",
    })
    return payload



def _enrich_dmarc_lookup_failed(f: Finding, domain: str) -> dict[str, Any]:
    evidence = _get_evidence_dict(f)
    resolver_status = str(evidence.get("resolver_status") or "").lower()

    payload = _default_finding_payload(f, domain)
    payload.update({
        "business_title": "DMARC protection could not be validated",
        "business_impact": (
            "The scan could not confirm whether DMARC is correctly published. "
            "That leaves uncertainty around how well the domain is protected against email impersonation."
        ),
        "why_it_matters": (
            "When DMARC validation fails, it becomes unclear whether receiving mail systems can enforce a policy against spoofed email."
        ),
        "effort": "Low to Medium",
        "technical_complexity": "Low",
        "steps": [
            "Verify that the domain resolves correctly in public DNS.",
            "Check the _dmarc TXT record directly from your DNS provider panel.",
            "Validate the authoritative name servers for availability and correct delegation.",
            "Repeat the lookup from multiple public resolvers.",
            "Re-run the scan after the DNS issue is resolved.",
        ],
    })

    if resolver_status:
        payload["business_title"] = f"DMARC validation failed {_resolver_suffix(resolver_status)}"

    return payload



def _enrich_spf_missing(f: Finding, domain: str) -> dict[str, Any]:
    payload = _default_finding_payload(f, domain)
    payload.update({
        "business_title": "Email sender authorization is not clearly defined",
        "business_impact": (
            "Without SPF, receiving mail systems cannot easily verify which servers are allowed to send mail for your domain. "
            "This can increase spoofing risk and weaken trust in legitimate outbound email."
        ),
        "why_it_matters": (
            "SPF is one of the basic controls for business email trust. Missing it makes sender verification less reliable."
        ),
        "effort": "Low (< 15 minutes)",
        "technical_complexity": "Low",
        "steps": [
            "List the services that legitimately send email on behalf of the domain.",
            "Open the DNS management panel.",
            "Create or update the TXT record that contains the SPF policy.",
            "Start with a minimal policy covering known senders.",
            "Wait for propagation and re-run the scan.",
        ],
        "copy_paste_snippet": "v=spf1 include:_spf.google.com ~all",
    })
    return payload



def _enrich_spf_lookup_failed(f: Finding, domain: str) -> dict[str, Any]:
    evidence = _get_evidence_dict(f)
    resolver_status = str(evidence.get("resolver_status") or "").lower()

    payload = _default_finding_payload(f, domain)
    payload.update({
        "business_title": "SPF validation could not be completed",
        "business_impact": (
            "The scan could not confirm whether SPF is configured correctly. "
            "That creates uncertainty around email sender validation and outbound email trust."
        ),
        "why_it_matters": (
            "If SPF cannot be validated at lookup time, defenders lose confidence in whether sender authorization is working as intended."
        ),
        "effort": "Low to Medium",
        "technical_complexity": "Low",
        "steps": [
            "Verify that the domain resolves correctly in DNS.",
            "Check whether TXT lookups succeed from multiple public resolvers.",
            "Confirm there are no malformed or oversized SPF/TXT records.",
            "Review the DNS provider for temporary lookup issues.",
            "Re-run the scan after resolution.",
        ],
    })

    if resolver_status:
        payload["business_title"] = f"SPF validation failed {_resolver_suffix(resolver_status)}"

    return payload



def _enrich_mx_missing(f: Finding, domain: str) -> dict[str, Any]:
    payload = _default_finding_payload(f, domain)
    payload.update({
        "business_title": "Inbound business email may not be reachable",
        "business_impact": (
            "If the domain is intended to receive email, missing MX records can cause lost messages, broken contact flows, and operational disruption."
        ),
        "why_it_matters": (
            "MX records tell other mail systems where to deliver email. Missing them can affect support, sales, and routine communication channels."
        ),
        "effort": "Low",
        "technical_complexity": "Low",
        "steps": [
            "Confirm whether the domain should receive inbound email.",
            "Identify the correct mail provider or mail gateway.",
            "Add the required MX records in the DNS panel.",
            "Validate priorities and provider-specific settings.",
            "Wait for propagation and re-run the scan.",
        ],
        "copy_paste_snippet": "MX 10 mail.example.com.",
    })
    return payload



def _enrich_mx_lookup_failed(f: Finding, domain: str) -> dict[str, Any]:
    evidence = _get_evidence_dict(f)
    resolver_status = str(evidence.get("resolver_status") or "").lower()

    payload = _default_finding_payload(f, domain)
    payload.update({
        "business_title": "Inbound email routing could not be validated",
        "business_impact": (
            "The scan could not confirm whether inbound email is configured correctly, which creates uncertainty around mail routing and business continuity."
        ),
        "why_it_matters": (
            "When MX validation fails, it becomes unclear whether the domain can reliably receive business email."
        ),
        "effort": "Low to Medium",
        "technical_complexity": "Low",
        "steps": [
            "Check whether the domain resolves correctly in DNS.",
            "Verify authoritative name servers and DNS availability.",
            "Repeat the MX lookup from multiple public resolvers.",
            "Check for temporary DNS provider issues.",
            "Re-run the scan after the issue is resolved.",
        ],
    })

    if resolver_status:
        payload["business_title"] = f"MX validation failed {_resolver_suffix(resolver_status)}"

    return payload



def _enrich_dns_resolution_failure(f: Finding, domain: str) -> dict[str, Any]:
    evidence = _get_evidence_dict(f)
    resolver_status = str(evidence.get("resolver_status") or "").lower()
    resolver_stage = str(evidence.get("resolver_stage") or "").lower()

    payload = _default_finding_payload(f, domain)
    payload.update({
        "business_title": "Core domain resolution appears unreliable or broken",
        "business_impact": (
            "If the domain does not resolve correctly in public DNS, multiple downstream services can be affected, including web trust, email validation, and service reachability."
        ),
        "why_it_matters": (
            "DNS resolution is foundational. When it breaks, several visible controls and services can fail at the same time."
        ),
        "effort": "Medium",
        "technical_complexity": "Low to Medium",
        "steps": [
            "Verify that the domain exists and is active at the registrar level.",
            "Check authoritative name servers and delegation.",
            "Confirm the zone is published correctly.",
            "Test resolution from multiple public resolvers.",
            "Re-run the scan after the resolution issue is fixed.",
        ],
    })

    if resolver_status:
        payload["business_title"] = f"Public DNS resolution failed {_resolver_suffix(resolver_status)}"

    if resolver_stage == "dmarc_lookup":
        payload["business_impact"] = (
            "The scan could not validate DMARC because DNS resolution failed during the DMARC lookup stage."
        )
    elif resolver_stage == "spf_lookup":
        payload["business_impact"] = (
            "The scan could not validate SPF because DNS resolution failed during the SPF lookup stage."
        )
    elif resolver_stage == "mx_lookup":
        payload["business_impact"] = (
            "The scan could not validate inbound email routing because DNS resolution failed during the MX lookup stage."
        )

    return payload



def _enrich_subdomain_exposure(f: Finding, domain: str) -> dict[str, Any]:
    evidence = _get_evidence_dict(f)
    count = evidence.get("count")

    payload = _default_finding_payload(f, domain)
    payload.update({
        "business_title": "Publicly visible subdomains may be expanding the attack surface",
        "business_impact": (
            "A large or unmanaged set of public subdomains can expose forgotten services, test systems, or misconfigured hosts to attackers."
        ),
        "why_it_matters": (
            "Every visible subdomain can become a reconnaissance point or an entry path if it is not actively maintained."
        ),
        "effort": "Low to Medium",
        "technical_complexity": "Low",
        "steps": [
            "Review the list of observed subdomains.",
            "Identify inactive, legacy, test, or duplicate entries.",
            "Remove or restrict unnecessary public subdomains.",
            "Maintain an updated inventory of active internet-facing assets.",
        ],
    })

    if isinstance(count, int):
        payload["business_impact"] = (
            f"{count} public subdomains were observed. If they are not actively managed, they may create avoidable exposure and reconnaissance opportunities."
        )

    return payload


def _enrich_subdomain_lookup_failed(f: Finding, domain: str) -> dict[str, Any]:
    payload = _default_finding_payload(f, domain)
    payload.update({
        "business_title": "Passive subdomain visibility could not be confirmed",
        "business_impact": (
            "The passive subdomain check did not complete successfully, so external asset visibility may be incomplete."
        ),
        "why_it_matters": (
            "If passive asset discovery fails, the reported internet-facing surface may be incomplete and should not be treated as a full inventory."
        ),
        "effort": "Low",
        "technical_complexity": "Low",
        "steps": [
            "Repeat the passive subdomain check later.",
            "Validate subdomain exposure with an alternative passive source.",
            "Compare discovered assets against the known internet-facing inventory.",
            "Re-run the scan after validation.",
        ],
    })
    return payload

def _enrich_tls_issue(f: Finding, domain: str) -> dict[str, Any]:
    payload = _default_finding_payload(f, domain)
    payload.update({
        "business_title": "Secure website trust may be impaired",
        "business_impact": (
            "Users, partners, or monitoring systems may be unable to establish a trusted HTTPS connection, which can reduce reliability and confidence in the domain."
        ),
        "why_it_matters": (
            "TLS issues affect browser trust, integrations, monitoring, and the overall perception of security maturity."
        ),
        "effort": "Medium",
        "technical_complexity": "Medium",
        "steps": [
            "Verify that the web service is reachable on port 443.",
            "Check the certificate, hostname binding, and reverse proxy configuration.",
            "Confirm that the full certificate chain is valid.",
            "Review renewal status and automated certificate management.",
            "Run the scan again after remediation.",
        ],
    })
    return payload



def _enrich_generic_dns_issue(f: Finding, domain: str) -> dict[str, Any]:
    payload = _default_finding_payload(f, domain)
    payload.update({
        "business_title": "DNS configuration should be reviewed",
        "business_impact": (
            "Incorrect or incomplete DNS records can affect trust, service availability, and the reliability of email- or web-related controls."
        ),
        "why_it_matters": (
            "DNS is a foundational dependency for internet-facing services. Even small errors can have visible external impact."
        ),
        "effort": "Low to Medium",
        "technical_complexity": "Low to Medium",
        "steps": [
            "Review the affected record against the intended configuration.",
            "Update the record in the DNS provider panel.",
            "Wait for propagation.",
            "Re-run the scan to verify the issue is resolved.",
        ],
    })
    return payload



def enrich_finding(f: Finding, domain: str) -> dict[str, Any]:
    title = (f.title or "").lower()
    category = (f.category or "").lower()
    evidence = _get_evidence_dict(f)
    check_type = (evidence.get("check_type") or "").lower()

    if category == "dns" and check_type in {"dmarc_missing", "dmarc_invalid"}:
        return _enrich_dmarc_missing(f, domain)

    if category == "dns" and check_type == "dmarc_lookup_failed":
        return _enrich_dmarc_lookup_failed(f, domain)

    if category == "dns" and check_type == "spf_missing":
        return _enrich_spf_missing(f, domain)

    if category == "dns" and check_type == "spf_lookup_failed":
        return _enrich_spf_lookup_failed(f, domain)

    if category == "dns" and check_type == "mx_missing":
        return _enrich_mx_missing(f, domain)

    if category == "dns" and check_type == "mx_lookup_failed":
        return _enrich_mx_lookup_failed(f, domain)

    if category == "dns" and "does not resolve in dns" in title:
        return _enrich_dns_resolution_failure(f, domain)

    if category == "subdomain":
        title_l = (f.title or "").lower()
        evidence = _get_evidence_dict(f)
        check_type = (evidence.get("check_type") or "").lower()

        if (
                "failed" in title_l
                or "timeout" in title_l
                or check_type in {"subdomain_lookup_failed", "passive_lookup_failed"}
                or evidence.get("error")
        ):
            return _enrich_subdomain_lookup_failed(f, domain)

        return _enrich_subdomain_exposure(f, domain)

    if category in {"ssl", "tls"}:
        return _enrich_tls_issue(f, domain)

    if category == "dns":
        return _enrich_generic_dns_issue(f, domain)

    return _default_finding_payload(f, domain)
