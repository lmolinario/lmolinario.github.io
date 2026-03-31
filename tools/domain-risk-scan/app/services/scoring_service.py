SEVERITY_WEIGHTS = {
    "low": 5,
    "medium": 12,
    "high": 20,
    "critical": 35,
}

CATEGORY_CAPS = {
    "dns": 30,
    "ssl": 20,
    "subdomain": 15,
}


def calculate_score(findings: list[dict]) -> int:
    category_totals: dict[str, int] = {}

    for finding in findings:
        category = finding["category"]
        severity = finding["severity"]

        weight = SEVERITY_WEIGHTS.get(severity, 0)
        category_totals[category] = category_totals.get(category, 0) + weight

    total_risk = 0
    for category, risk in category_totals.items():
        cap = CATEGORY_CAPS.get(category, risk)
        total_risk += min(risk, cap)

    return max(0, 100 - total_risk)