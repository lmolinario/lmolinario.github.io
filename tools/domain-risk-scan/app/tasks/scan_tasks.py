from app.core.database import SessionLocal
from app.services.scan_service import (
    get_scan,
    replace_findings,
    update_scan_completed,
    update_scan_failed,
    set_scan_running,
)
from app.services.scoring_service import calculate_score
from app.scanners.dns_scanner import scan_dns
from app.scanners.ssl_scanner import scan_ssl
from app.scanners.subdomain_scanner import scan_subdomains
from app.services.report_service import _score_to_risk_level
from app.services.analytics_service import track_event

try:
    from app.tasks.celery_app import celery
except Exception:
    celery = None


def _severity_rank(severity: str | None) -> int:
    order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }
    return order.get((severity or "").lower(), 0)


def _finding_priority(finding: dict) -> int:
    title = (finding.get("title") or "").lower()
    category = (finding.get("category") or "").lower()
    severity = finding.get("severity")
    evidence = finding.get("evidence_json") or {}
    check_type = (evidence.get("check_type") or "").lower()

    score = 0
    score += _severity_rank(severity) * 100

    if category == "dns":
        score += 40

        if check_type in {"dmarc_missing", "dmarc_invalid"} or "dmarc" in title:
            score += 50

        if check_type == "dmarc_lookup_failed":
            score += 30

        if check_type == "spf_missing" or "spf record missing" in title:
            score += 40

        if check_type == "spf_lookup_failed":
            score += 20

        if check_type == "mx_missing" or "mx records missing" in title:
            score += 35

        if check_type == "mx_lookup_failed":
            score += 25

        if check_type in {"dns_lookup_failure"} or "does not resolve in dns" in title:
            score += 45

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

    if (finding.get("recommendation") or "").strip():
        score += 10

    return score


def _ordered_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: (
            _finding_priority(f),
            _severity_rank(f.get("severity")),
            f.get("category") or "",
            f.get("title") or "",
        ),
        reverse=True,
    )


def execute_scan(scan_id: int):
    db = SessionLocal()

    try:
        scan = get_scan(db, scan_id)
        if not scan:
            return

        set_scan_running(db, scan)

        domain = scan.domain
        findings: list[dict] = []

        findings.extend(scan_dns(domain))
        findings.extend(scan_ssl(domain))
        findings.extend(scan_subdomains(domain))

        replace_findings(db, scan_id, findings)

        score = calculate_score(findings)
        ordered_findings = _ordered_findings(findings)

        by_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for f in findings:
            sev = (f.get("severity") or "").lower()
            if sev in by_severity:
                by_severity[sev] += 1

        summary = {
            "domain": domain,
            "findings_count": len(findings),
            "by_severity": by_severity,
            "top_issues": [
                {
                    "category": f.get("category"),
                    "severity": f.get("severity"),
                    "title": f.get("title"),
                }
                for f in ordered_findings[:5]
            ],
            "risk_level": _score_to_risk_level(score),
        }

        update_scan_completed(db, scan, score, summary)
        track_event(db, scan.id, "scan_completed")

    except Exception as e:
        print(f"[execute_scan] ERROR for scan_id={scan_id}: {e!r}")
        db.rollback()

        try:
            scan = get_scan(db, scan_id)
            if scan:
                update_scan_failed(db, scan, str(e))
        except Exception as inner_e:
            print(f"[execute_scan] FAILED to mark scan as failed for scan_id={scan_id}: {inner_e!r}")
            db.rollback()

        raise

    finally:
        db.close()


if celery is not None:
    @celery.task(name="app.tasks.scan_tasks.run_scan_task")
    def run_scan_task(scan_id: int):
        execute_scan(scan_id)
else:
    def run_scan_task(scan_id: int):
        execute_scan(scan_id)