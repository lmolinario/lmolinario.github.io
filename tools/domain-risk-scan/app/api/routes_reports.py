from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.scan import Scan
from app.schemas.report import ReportResponse
from app.services.report_service import (
    build_report_payload,
    get_or_create_report,
    persist_report_payload,
)

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _get_scan_or_404(db: Session, scan_id: int) -> Scan:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}", response_model=ReportResponse)
def get_report(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan_or_404(db, scan_id)

    if scan.status != "completed":
        raise HTTPException(
            status_code=409,
            detail=f"Scan {scan_id} is not ready yet. Current status: {scan.status}",
        )

    report = get_or_create_report(db, scan.id)
    report = persist_report_payload(db, report, scan)

    payload = build_report_payload(
        db=db,
        scan=scan,
        is_paid=report.is_paid,
    )

    # Keep API and persisted report snapshot aligned.
    # If the report already contains stored AI fields from a paid snapshot,
    # build_report_payload() already merges them through report_service.
    return ReportResponse(**payload)
