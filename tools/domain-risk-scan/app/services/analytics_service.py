from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.analytics_event import AnalyticsEvent


def track_event(
    db: Session,
    scan_id: int,
    event_type: str,
    metadata: dict | None = None,
) -> AnalyticsEvent:
    if event_type in {"scan_completed", "report_unlock_clicked", "checkout_created", "checkout_completed", "checkout_canceled"}:
        existing = (
            db.query(AnalyticsEvent)
            .filter(
                AnalyticsEvent.scan_id == scan_id,
                AnalyticsEvent.event_type == event_type,
            )
            .first()
        )
        if existing:
            return existing

    event = AnalyticsEvent(
        scan_id=scan_id,
        event_type=event_type,
        metadata_json=metadata or {},
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def get_funnel_metrics(db: Session) -> dict:
    rows = (
        db.query(
            AnalyticsEvent.event_type,
            func.count(AnalyticsEvent.id),
        )
        .group_by(AnalyticsEvent.event_type)
        .all()
    )

    counts = {event_type: count for event_type, count in rows}

    scan_completed = counts.get("scan_completed", 0)
    report_unlock_clicked = counts.get("report_unlock_clicked", 0)
    checkout_created = counts.get("checkout_created", 0)
    checkout_completed = counts.get("checkout_completed", 0)
    checkout_canceled = counts.get("checkout_canceled", 0)

    def pct(part: int, whole: int) -> float:
        if whole <= 0:
            return 0.0
        return round((part / whole) * 100, 2)

    return {
        "scan_completed": scan_completed,
        "report_unlock_clicked": report_unlock_clicked,
        "checkout_created": checkout_created,
        "checkout_completed": checkout_completed,
        "checkout_canceled": checkout_canceled,
        "unlock_click_rate": pct(report_unlock_clicked, scan_completed),
        "checkout_created_rate": pct(checkout_created, scan_completed),
        "checkout_completed_rate": pct(checkout_completed, scan_completed),
        "checkout_completion_from_created_rate": pct(checkout_completed, checkout_created),
    }