import httpx


CRT_SH_URL = "https://crt.sh/"


def _extract_unique_subdomains(domain: str, rows: list[dict]) -> list[str]:
    found = set()

    for row in rows:
        name_value = row.get("name_value", "")
        for item in name_value.splitlines():
            item = item.strip().lower()
            if not item:
                continue

            if item.startswith("*."):
                item = item[2:]

            if item == domain or item.endswith(f".{domain}"):
                found.add(item)

    return sorted(found)


def scan_subdomains(domain: str) -> list[dict]:
    findings = []

    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            response = client.get(CRT_SH_URL, params={"q": f"%.{domain}", "output": "json"})
            response.raise_for_status()
            rows = response.json()

        subdomains = _extract_unique_subdomains(domain, rows)

        if len(subdomains) >= 20:
            findings.append({
                "category": "subdomain",
                "severity": "medium",
                "title": "Large public subdomain footprint",
                "description": "Many public subdomains were identified through certificate transparency logs.",
                "evidence_json": {
                    "count": len(subdomains),
                    "sample": subdomains[:15],
                    "check_type": "subdomain_footprint",
                    "scan_quality": "complete",
                },
                "recommendation": "Review whether all public subdomains are still required and properly protected."
            })
        elif len(subdomains) >= 5:
            findings.append({
                "category": "subdomain",
                "severity": "low",
                "title": "Multiple public subdomains detected",
                "description": "The domain has several publicly visible subdomains.",
                "evidence_json": {
                    "count": len(subdomains),
                    "sample": subdomains[:10],
                    "check_type": "subdomain_footprint",
                    "scan_quality": "complete",
                },
                "recommendation": "Maintain an up-to-date inventory of exposed subdomains."
            })

    except Exception as e:
        # Non trasformare il fallimento di una fonte esterna in un finding di rischio.
        findings.append({
            "category": "scanner",
            "severity": "info",
            "title": "Passive subdomain coverage incomplete",
            "description": "The passive subdomain source did not respond correctly, so external asset coverage may be incomplete.",
            "evidence_json": {
                "error": str(e),
                "check_type": "subdomain_source_error",
                "scan_quality": "partial",
                "source": "crt.sh",
            },
            "recommendation": "Repeat the passive lookup later or validate subdomains with an additional passive source."
        })

    return findings