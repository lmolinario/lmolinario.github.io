from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.models.finding import Finding


def create_scan(db: Session, domain: str) -> Scan:
    scan = Scan(domain=domain, status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_scan(db: Session, scan_id: int) -> Scan | None:
    return db.query(Scan).filter(Scan.id == scan_id).first()


def get_recent_completed_scan_by_domain(
    db: Session,
    domain: str,
    max_age_hours: int = 24,
) -> Scan | None:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

    return (
        db.query(Scan)
        .filter(
            Scan.domain == domain,
            Scan.status == "completed",
            Scan.created_at >= cutoff,
        )
        .order_by(Scan.created_at.desc())
        .first()
    )


def get_findings_by_scan(db: Session, scan_id: int) -> list[Finding]:
    return (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .order_by(Finding.id.asc())
        .all()
    )


def delete_findings_by_scan(db: Session, scan_id: int) -> None:
    try:
        db.query(Finding).filter(Finding.scan_id == scan_id).delete(synchronize_session=False)
        db.commit()
    except Exception:
        db.rollback()
        raise


def replace_findings(db: Session, scan_id: int, findings: list[dict]) -> None:
    """
    Replace all findings for a scan atomically.
    Useful if a scan is re-run on the same scan_id.
    """
    try:
        db.query(Finding).filter(Finding.scan_id == scan_id).delete(synchronize_session=False)

        for item in findings:
            finding = Finding(
                scan_id=scan_id,
                category=item["category"],
                severity=item["severity"],
                title=item["title"],
                description=item["description"],
                evidence_json=item.get("evidence_json"),
                recommendation=item.get("recommendation"),
            )
            db.add(finding)

        db.commit()
    except Exception:
        db.rollback()
        raise


def save_findings(db: Session, scan_id: int, findings: list[dict]) -> None:
    """
    Backward-compatible insert-only save.
    Prefer replace_findings() for scan executions.
    """
    try:
        for item in findings:
            finding = Finding(
                scan_id=scan_id,
                category=item["category"],
                severity=item["severity"],
                title=item["title"],
                description=item["description"],
                evidence_json=item.get("evidence_json"),
                recommendation=item.get("recommendation"),
            )
            db.add(finding)
        db.commit()
    except Exception:
        db.rollback()
        raise


def update_scan_completed(db: Session, scan: Scan, score: int, summary: dict) -> None:
    scan.status = "completed"
    scan.score = score
    scan.summary_json = summary
    db.commit()
    db.refresh(scan)


def update_scan_failed(db: Session, scan: Scan, error_message: str) -> None:
    scan.status = "failed"
    scan.summary_json = {"error": error_message}
    db.commit()
    db.refresh(scan)


def set_scan_running(db: Session, scan: Scan) -> None:
    scan.status = "running"
    db.commit()
    db.refresh(scan)