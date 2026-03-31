import dns.exception
import dns.resolver


def _resolver_status_from_exception(exc: Exception) -> str:
    if isinstance(exc, dns.resolver.NXDOMAIN):
        return "nxdomain"
    if isinstance(exc, dns.resolver.NoNameservers):
        return "no_nameservers"
    if isinstance(exc, dns.resolver.NoAnswer):
        return "no_answer"
    if isinstance(exc, dns.resolver.LifetimeTimeout):
        return "timeout"
    return "unknown"


def _dns_resolution_title(stage: str, status: str) -> str:
    stage = stage.upper()

    if status == "nxdomain":
        return "Domain does not resolve in DNS"
    if status == "timeout":
        return f"{stage} lookup timed out"
    if status == "no_nameservers":
        return f"{stage} lookup failed due to nameserver issues"
    if status == "no_answer":
        return f"{stage} record missing"
    return f"{stage} lookup failed"


def _dns_resolution_description(stage: str, status: str, domain_checked: str) -> str:
    stage = stage.upper()

    if status == "nxdomain":
        return f"The domain {domain_checked} does not resolve in DNS."
    if status == "timeout":
        return f"The scan could not complete the {stage} lookup because the DNS query timed out."
    if status == "no_nameservers":
        return f"The scan could not complete the {stage} lookup because no working nameservers responded."
    if status == "no_answer":
        return f"No {stage} record was returned for {domain_checked}."
    return f"The scan could not complete the {stage} lookup due to a DNS resolution issue."


def scan_dns(domain: str) -> list[dict]:
    findings = []

    # SPF
    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        txt_values = [r.to_text().strip('"') for r in txt_records]
        has_spf = any("v=spf1" in txt.lower() for txt in txt_values)

        if not has_spf:
            findings.append({
                "category": "dns",
                "severity": "high",
                "title": "SPF record missing",
                "description": "The domain does not publish a valid SPF record.",
                "evidence_json": {
                    "records": txt_values,
                    "domain_checked": domain,
                    "check_type": "spf_missing",
                },
                "recommendation": "Publish an SPF record to authorize legitimate outbound email servers.",
            })

    except dns.resolver.NoAnswer as e:
        findings.append({
            "category": "dns",
            "severity": "high",
            "title": "SPF record missing",
            "description": "No TXT records containing a valid SPF policy were returned for the domain.",
            "evidence_json": {
                "domain_checked": domain,
                "error": str(e),
                "resolver_status": "no_answer",
                "check_type": "spf_missing",
            },
            "recommendation": "Publish an SPF record to authorize legitimate outbound email servers.",
        })

    except dns.resolver.NXDOMAIN as e:
        findings.append({
            "category": "dns",
            "severity": "high",
            "title": _dns_resolution_title("spf", "nxdomain"),
            "description": _dns_resolution_description("spf", "nxdomain", domain),
            "evidence_json": {
                "domain_checked": domain,
                "error": str(e),
                "resolver_stage": "spf_lookup",
                "resolver_status": "nxdomain",
                "check_type": "spf_lookup_failed",
            },
            "recommendation": "Verify that the domain is correct and that authoritative DNS resolution is working properly.",
        })

    except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, dns.exception.DNSException) as e:
        status = _resolver_status_from_exception(e)
        findings.append({
            "category": "dns",
            "severity": "medium",
            "title": _dns_resolution_title("spf", status),
            "description": _dns_resolution_description("spf", status, domain),
            "evidence_json": {
                "error": str(e),
                "domain_checked": domain,
                "resolver_stage": "spf_lookup",
                "resolver_status": status,
                "check_type": "spf_lookup_failed",
            },
            "recommendation": "Review DNS availability and confirm that TXT records can be resolved correctly for the domain.",
        })

    # DMARC
    dmarc_domain = f"_dmarc.{domain}"
    try:
        dmarc_records = dns.resolver.resolve(dmarc_domain, "TXT")
        dmarc_values = [r.to_text().strip('"') for r in dmarc_records]
        has_dmarc = any("v=dmarc1" in txt.lower() for txt in dmarc_values)

        if not has_dmarc:
            findings.append({
                "category": "dns",
                "severity": "high",
                "title": "DMARC record invalid or incomplete",
                "description": "The domain publishes TXT data under _dmarc, but no valid DMARC policy was detected.",
                "evidence_json": {
                    "records": dmarc_values,
                    "domain_checked": dmarc_domain,
                    "check_type": "dmarc_invalid",
                },
                "recommendation": "Publish a valid DMARC record, starting with a monitoring policy such as p=none.",
            })

    except dns.resolver.NoAnswer:
        findings.append({
            "category": "dns",
            "severity": "high",
            "title": "DMARC record missing",
            "description": "No DMARC record was found for the domain.",
            "evidence_json": {
                "domain_checked": dmarc_domain,
                "resolver_status": "no_answer",
                "check_type": "dmarc_missing",
            },
            "recommendation": "Add a DMARC record to reduce spoofing risk and improve email trust.",
        })

    except dns.resolver.NXDOMAIN as e:
        findings.append({
            "category": "dns",
            "severity": "high",
            "title": _dns_resolution_title("dmarc", "nxdomain"),
            "description": _dns_resolution_description("dmarc", "nxdomain", domain),
            "evidence_json": {
                "domain_checked": dmarc_domain,
                "error": str(e),
                "resolver_stage": "dmarc_lookup",
                "resolver_status": "nxdomain",
                "check_type": "dmarc_lookup_failed",
            },
            "recommendation": "Verify that the domain is correct and that authoritative DNS resolution is working properly.",
        })

    except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, dns.exception.DNSException) as e:
        status = _resolver_status_from_exception(e)
        findings.append({
            "category": "dns",
            "severity": "medium",
            "title": _dns_resolution_title("dmarc", status),
            "description": _dns_resolution_description("dmarc", status, dmarc_domain),
            "evidence_json": {
                "domain_checked": dmarc_domain,
                "error": str(e),
                "resolver_stage": "dmarc_lookup",
                "resolver_status": status,
                "check_type": "dmarc_lookup_failed",
            },
            "recommendation": "Verify DNS availability and confirm that the _dmarc TXT record can be resolved correctly.",
        })

    # MX
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        mx_values = [r.exchange.to_text() for r in mx_records]

        if not mx_values:
            findings.append({
                "category": "dns",
                "severity": "medium",
                "title": "MX records missing",
                "description": "The domain does not appear to have any configured mail servers.",
                "evidence_json": {
                    "records": [],
                    "domain_checked": domain,
                    "check_type": "mx_missing",
                },
                "recommendation": "If the domain should receive email, configure MX records for the intended mail service.",
            })

    except dns.resolver.NoAnswer:
        findings.append({
            "category": "dns",
            "severity": "medium",
            "title": "MX records missing",
            "description": "No MX records were returned for the domain.",
            "evidence_json": {
                "domain_checked": domain,
                "check_type": "mx_missing",
                "resolver_status": "no_answer",
            },
            "recommendation": "If the domain should receive email, configure MX records for the intended mail service.",
        })

    except dns.resolver.NXDOMAIN as e:
        findings.append({
            "category": "dns",
            "severity": "high",
            "title": _dns_resolution_title("mx", "nxdomain"),
            "description": _dns_resolution_description("mx", "nxdomain", domain),
            "evidence_json": {
                "domain_checked": domain,
                "error": str(e),
                "resolver_stage": "mx_lookup",
                "check_type": "mx_lookup_failed",
                "resolver_status": "nxdomain",
            },
            "recommendation": "Verify that the domain is correct and that authoritative DNS resolution is working properly.",
        })

    except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, dns.exception.DNSException) as e:
        status = _resolver_status_from_exception(e)
        findings.append({
            "category": "dns",
            "severity": "medium",
            "title": _dns_resolution_title("mx", status),
            "description": _dns_resolution_description("mx", status, domain),
            "evidence_json": {
                "domain_checked": domain,
                "error": str(e),
                "resolver_stage": "mx_lookup",
                "resolver_status": status,
                "check_type": "mx_lookup_failed",
            },
            "recommendation": "Verify whether the domain is expected to receive email and confirm the MX setup with your DNS provider.",
        })

    return findings