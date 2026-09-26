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


def _resolve_record(domain: str, record_type: str):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return {
            "status": "ok",
            "answers": list(answers),
        }
    except Exception as exc:
        return {
            "status": _resolver_status_from_exception(exc),
            "error": exc,
            "answers": [],
        }


def _is_dns_incomplete(status: str) -> bool:
    return status in {"timeout", "no_nameservers", "unknown"}


def _txt_values(result: dict) -> list[str]:
    if result["status"] != "ok":
        return []

    return [
        answer.to_text().replace('" "', "").strip('"')
        for answer in result["answers"]
    ]


def _mx_values(result: dict) -> list[dict]:
    if result["status"] != "ok":
        return []

    values = []
    for answer in result["answers"]:
        values.append({
            "preference": int(answer.preference),
            "exchange": answer.exchange.to_text(),
        })
    return values


def _is_null_mx(mx_values: list[dict]) -> bool:
    return (
        len(mx_values) == 1
        and mx_values[0]["preference"] == 0
        and mx_values[0]["exchange"] == "."
    )


def _coverage_note(
    *,
    title: str,
    description: str,
    check_type: str,
    recommendation: str,
    evidence: dict | None = None,
) -> dict:
    payload = {
        "category": "scanner",
        "severity": "info",
        "finding_type": "coverage",
        "title": title,
        "description": description,
        "evidence_json": {
            "check_type": check_type,
            "scan_quality": "partial",
            **(evidence or {}),
        },
        "recommendation": recommendation,
    }
    return payload


def scan_dns(domain: str) -> list[dict]:
    findings: list[dict] = []

    # ------------------------------------------------------------------
    # 1. Base public DNS resolution
    # ------------------------------------------------------------------

    a_result = _resolve_record(domain, "A")
    aaaa_result = _resolve_record(domain, "AAAA")

    base_ok = (
        a_result["status"] == "ok"
        or aaaa_result["status"] == "ok"
    )

    if not base_ok:
        statuses = {a_result["status"], aaaa_result["status"]}

        if statuses == {"nxdomain"} or statuses == {"nxdomain", "no_answer"}:
            return [
                _coverage_note(
                    title="Base domain does not resolve in public DNS",
                    description=(
                        f"The domain {domain} did not resolve through public DNS "
                        "during the scan. Email-related controls were not scored "
                        "because the base domain itself could not be validated."
                    ),
                    check_type="domain_resolution_incomplete",
                    recommendation=(
                        "Verify the domain name, DNS delegation and authoritative "
                        "public DNS resolution before relying on email-security results."
                    ),
                    evidence={
                        "domain_checked": domain,
                        "a_status": a_result["status"],
                        "aaaa_status": aaaa_result["status"],
                    },
                )
            ]

        if any(_is_dns_incomplete(status) for status in statuses):
            return [
                _coverage_note(
                    title="DNS validation incomplete",
                    description=(
                        "The scan could not reliably validate DNS-based controls "
                        "because base-domain resolution did not complete successfully."
                    ),
                    check_type="dns_resolution_incomplete",
                    recommendation=(
                        "Repeat the scan and verify public DNS availability before "
                        "relying on the result."
                    ),
                    evidence={
                        "domain_checked": domain,
                        "a_status": a_result["status"],
                        "aaaa_status": aaaa_result["status"],
                    },
                )
            ]

    # ------------------------------------------------------------------
    # 2. Collect email DNS evidence BEFORE generating findings
    # ------------------------------------------------------------------

    txt_result = _resolve_record(domain, "TXT")
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_result = _resolve_record(dmarc_domain, "TXT")
    mx_result = _resolve_record(domain, "MX")

    txt_values = _txt_values(txt_result)
    dmarc_values = _txt_values(dmarc_result)
    mx_values = _mx_values(mx_result)

    spf_records = [
        value for value in txt_values
        if "v=spf1" in value.lower()
    ]

    dmarc_records = [
        value for value in dmarc_values
        if "v=dmarc1" in value.lower()
    ]

    has_spf = bool(spf_records)
    has_dmarc = bool(dmarc_records)
    null_mx = _is_null_mx(mx_values)

    # ------------------------------------------------------------------
    # 3. Determine email posture from externally observable evidence
    # ------------------------------------------------------------------

    if null_mx:
        email_posture = "mail_disabled"
    elif mx_result["status"] == "ok" and mx_values:
        email_posture = "mail_enabled"
    elif mx_result["status"] in {"no_answer", "nxdomain"}:
        email_posture = "mail_undeclared"
    else:
        email_posture = "mail_lookup_incomplete"

    common_evidence = {
        "domain_checked": domain,
        "email_posture": email_posture,
        "mx_records": mx_values,
        "spf_records": spf_records,
        "dmarc_records": dmarc_records,
    }

    # ------------------------------------------------------------------
    # 4. Explicitly non-mail domain: Null MX
    # ------------------------------------------------------------------

    if email_posture == "mail_disabled":
        findings.append(
            _coverage_note(
                title="Domain explicitly does not accept email",
                description=(
                    "The domain publishes a Null MX record (MX 0 .), explicitly "
                    "indicating that it does not accept inbound email. Missing normal "
                    "MX infrastructure is therefore not treated as a security finding."
                ),
                check_type="mail_explicitly_disabled",
                recommendation=(
                    "No inbound MX remediation is required if this non-mail posture "
                    "is intentional. Consider a restrictive SPF policy and DMARC "
                    "policy appropriate to the domain's outbound-email intent."
                ),
                evidence={
                    **common_evidence,
                    "scan_quality": "complete",
                },
            )
        )
        return findings

    # ------------------------------------------------------------------
    # 5. No MX: intent cannot be established from public DNS alone
    # ------------------------------------------------------------------

    if email_posture == "mail_undeclared":
        findings.append(
            _coverage_note(
                title="Email usage is not declared by public DNS",
                description=(
                    "No normal MX or Null MX record was found. From external DNS "
                    "evidence alone, the scanner cannot determine whether the domain "
                    "is intentionally web-only or whether email configuration is "
                    "incomplete. Missing email controls are therefore not scored as "
                    "security findings."
                ),
                check_type="mail_intent_undeclared",
                recommendation=(
                    "Confirm the intended email posture. If the domain must receive "
                    "mail, configure the real mail provider and its MX records. If it "
                    "must not receive mail, consider publishing a Null MX (MX 0 .). "
                    "For domains that must not send mail, consider an SPF policy such "
                    "as v=spf1 -all. Configure DMARC according to the domain's actual "
                    "email use rather than assuming a mail provider."
                ),
                evidence={
                    **common_evidence,
                    "mx_resolver_status": mx_result["status"],
                    "spf_resolver_status": txt_result["status"],
                    "dmarc_resolver_status": dmarc_result["status"],
                    "scan_quality": "complete",
                },
            )
        )
        return findings

    # ------------------------------------------------------------------
    # 6. MX lookup incomplete: do not infer mail configuration
    # ------------------------------------------------------------------

    if email_posture == "mail_lookup_incomplete":
        findings.append(
            _coverage_note(
                title="Email posture validation incomplete",
                description=(
                    "The MX lookup did not complete reliably, so the scanner cannot "
                    "determine whether the domain is mail-enabled."
                ),
                check_type="mx_lookup_failed",
                recommendation=(
                    "Repeat the MX lookup and verify authoritative DNS availability "
                    "before relying on email-security conclusions."
                ),
                evidence={
                    **common_evidence,
                    "resolver_stage": "mx_lookup",
                    "resolver_status": mx_result["status"],
                },
            )
        )
        return findings

    # ------------------------------------------------------------------
    # 7. Mail-enabled domain: evaluate SPF
    # ------------------------------------------------------------------

    if txt_result["status"] == "ok":
        if not has_spf:
            findings.append({
                "category": "dns",
                "severity": "high",
                "title": "SPF record missing",
                "description": (
                    "The domain has active MX infrastructure but does not publish "
                    "a valid SPF policy."
                ),
                "evidence_json": {
                    **common_evidence,
                    "records": txt_values,
                    "check_type": "spf_missing",
                    "scan_quality": "complete",
                },
                "recommendation": (
                    "Publish an SPF policy that authorizes only the services that "
                    "actually send email for this domain. Do not add unverified "
                    "providers."
                ),
            })
    elif txt_result["status"] == "no_answer":
        findings.append({
            "category": "dns",
            "severity": "high",
            "title": "SPF record missing",
            "description": (
                "The domain has active MX infrastructure but no valid SPF policy "
                "was returned."
            ),
            "evidence_json": {
                **common_evidence,
                "resolver_status": "no_answer",
                "check_type": "spf_missing",
                "scan_quality": "complete",
            },
            "recommendation": (
                "Publish an SPF policy based on the domain's actual authorized "
                "outbound senders."
            ),
        })
    else:
        findings.append(
            _coverage_note(
                title="SPF validation incomplete",
                description=(
                    "The scan could not reliably complete SPF validation."
                ),
                check_type="spf_lookup_failed",
                recommendation=(
                    "Repeat the TXT lookup and verify authoritative DNS availability."
                ),
                evidence={
                    **common_evidence,
                    "resolver_stage": "spf_lookup",
                    "resolver_status": txt_result["status"],
                },
            )
        )

    # ------------------------------------------------------------------
    # 8. Mail-enabled domain: evaluate DMARC
    # ------------------------------------------------------------------

    if dmarc_result["status"] == "ok":
        if not has_dmarc:
            findings.append({
                "category": "dns",
                "severity": "high",
                "title": "DMARC record invalid or incomplete",
                "description": (
                    "The domain has active mail infrastructure, but no valid DMARC "
                    "policy was detected under _dmarc."
                ),
                "evidence_json": {
                    **common_evidence,
                    "records": dmarc_values,
                    "domain_checked": dmarc_domain,
                    "check_type": "dmarc_invalid",
                    "scan_quality": "complete",
                },
                "recommendation": (
                    "Publish a valid DMARC policy appropriate to the domain's real "
                    "mail flow and deployment stage."
                ),
            })
    elif dmarc_result["status"] in {"no_answer", "nxdomain"}:
        findings.append({
            "category": "dns",
            "severity": "high",
            "title": "DMARC record missing",
            "description": (
                "The domain has active mail infrastructure but no DMARC record "
                "was found."
            ),
            "evidence_json": {
                **common_evidence,
                "domain_checked": dmarc_domain,
                "resolver_status": dmarc_result["status"],
                "check_type": "dmarc_missing",
                "scan_quality": "complete",
            },
            "recommendation": (
                "Publish a DMARC policy appropriate to the domain's actual email "
                "configuration and enforcement readiness."
            ),
        })
    else:
        findings.append(
            _coverage_note(
                title="DMARC validation incomplete",
                description=(
                    "The scan could not reliably complete DMARC validation."
                ),
                check_type="dmarc_lookup_failed",
                recommendation=(
                    "Repeat the _dmarc TXT lookup and verify authoritative DNS "
                    "availability."
                ),
                evidence={
                    **common_evidence,
                    "domain_checked": dmarc_domain,
                    "resolver_stage": "dmarc_lookup",
                    "resolver_status": dmarc_result["status"],
                },
            )
        )

    return findings
