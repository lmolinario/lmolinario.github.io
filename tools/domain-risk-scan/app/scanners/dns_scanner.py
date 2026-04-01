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


def scan_dns(domain: str) -> list[dict]:
    findings = []

    # Primo check: il dominio base risolve?
    try:
        dns.resolver.resolve(domain, "A")
    except dns.resolver.NXDOMAIN as e:
        return [{
            "category": "dns",
            "severity": "high",
            "title": "Domain does not resolve in public DNS",
            "description": f"The domain {domain} does not currently resolve in public DNS.",
            "evidence_json": {
                "domain_checked": domain,
                "error": str(e),
                "resolver_status": "nxdomain",
                "check_type": "domain_resolution_failed",
                "scan_quality": "partial",
            },
            "recommendation": "Verify the domain name, DNS delegation, and authoritative public DNS resolution before assessing email-related controls."
        }]
    except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, dns.exception.DNSException) as e:
        status = _resolver_status_from_exception(e)
        return [{
            "category": "scanner",
            "severity": "info",
            "title": "DNS validation incomplete",
            "description": "The scan could not reliably validate DNS-based controls because DNS resolution did not complete successfully.",
            "evidence_json": {
                "domain_checked": domain,
                "error": str(e),
                "resolver_status": status,
                "check_type": "dns_resolution_incomplete",
                "scan_quality": "partial",
            },
            "recommendation": "Repeat the scan and verify public DNS availability before relying on the result."
        }]

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
                    "scan_quality": "complete",
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
                "scan_quality": "complete",
            },
            "recommendation": "Publish an SPF record to authorize legitimate outbound email servers.",
        })

    except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, dns.exception.DNSException) as e:
        status = _resolver_status_from_exception(e)
        findings.append({
            "category": "scanner",
            "severity": "info",
            "title": "SPF validation incomplete",
            "description": "The scan could not complete SPF validation due to a DNS lookup issue.",
            "evidence_json": {
                "error": str(e),
                "domain_checked": domain,
                "resolver_stage": "spf_lookup",
                "resolver_status": status,
                "check_type": "spf_lookup_incomplete",
                "scan_quality": "partial",
            },
            "recommendation": "Repeat the DNS lookup and verify TXT record resolution for the domain.",
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
                    "scan_quality": "complete",
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
                "scan_quality": "complete",
            },
            "recommendation": "Add a DMARC record to reduce spoofing risk and improve email trust.",
        })

    except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, dns.exception.DNSException) as e:
        status = _resolver_status_from_exception(e)
        findings.append({
            "category": "scanner",
            "severity": "info",
            "title": "DMARC validation incomplete",
            "description": "The scan could not complete DMARC validation due to a DNS lookup issue.",
            "evidence_json": {
                "domain_checked": dmarc_domain,
                "error": str(e),
                "resolver_stage": "dmarc_lookup",
                "resolver_status": status,
                "check_type": "dmarc_lookup_incomplete",
                "scan_quality": "partial",
            },
            "recommendation": "Repeat the lookup and verify that the _dmarc TXT record is externally resolvable.",
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
                    "scan_quality": "complete",
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
                "scan_quality": "complete",
            },
            "recommendation": "If the domain should receive email, configure MX records for the intended mail service.",
        })

    except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, dns.exception.DNSException) as e:
        status = _resolver_status_from_exception(e)
        findings.append({
            "category": "scanner",
            "severity": "info",
            "title": "MX validation incomplete",
            "description": "The scan could not complete MX validation due to a DNS lookup issue.",
            "evidence_json": {
                "domain_checked": domain,
                "error": str(e),
                "resolver_stage": "mx_lookup",
                "resolver_status": status,
                "check_type": "mx_lookup_incomplete",
                "scan_quality": "partial",
            },
            "recommendation": "Repeat the lookup and verify whether the domain is expected to receive email.",
        })

    return findings