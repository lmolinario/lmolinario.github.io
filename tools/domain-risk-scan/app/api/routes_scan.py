from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.services.report_service import _score_to_risk_level


from app.core.config import settings
from app.core.database import get_db
from app.schemas.scan import (
    ScanCreate,
    ScanCreateResponse,
    ScanStatusResponse,
    FindingsListResponse,
    FindingResponse,
)
from app.services.scan_service import (
    create_scan,
    get_scan,
    get_findings_by_scan,
    get_recent_completed_scan_by_domain,
)
from app.tasks.scan_tasks import run_scan_task
from app.utils.validators import normalize_domain, is_valid_domain

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanCreateResponse)
def create_scan_endpoint(payload: ScanCreate, db: Session = Depends(get_db)):
    domain = normalize_domain(payload.domain)

    if not is_valid_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain")

    cached_scan = get_recent_completed_scan_by_domain(
        db=db,
        domain=domain,
        max_age_hours=settings.scan_cache_hours,
    )
    if cached_scan:
        return ScanCreateResponse(
            scan_id=cached_scan.id,
            status=cached_scan.status,
            cached=True,
        )

    scan = create_scan(db, domain)
    run_scan_task.delay(scan.id)

    return ScanCreateResponse(
        scan_id=scan.id,
        status=scan.status,
        cached=False,
    )


@router.get("/{scan_id}", response_model=ScanStatusResponse)
def get_scan_endpoint(scan_id: int, db: Session = Depends(get_db)):
    scan = get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanStatusResponse(
        scan_id=scan.id,
        domain=scan.domain,
        status=scan.status,
        score=scan.score,
        summary=scan.summary_json,
        risk_level=_score_to_risk_level(scan.score),
    )


@router.get("/{scan_id}/findings", response_model=FindingsListResponse)
def get_scan_findings_endpoint(scan_id: int, db: Session = Depends(get_db)):
    scan = get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = get_findings_by_scan(db, scan_id)

    return FindingsListResponse(
        scan_id=scan.id,
        domain=scan.domain,
        findings=[
            FindingResponse(
                id=f.id,
                category=f.category,
                severity=f.severity,
                title=f.title,
                description=f.description,
                evidence_json=f.evidence_json,
                recommendation=f.recommendation,
            )
            for f in findings
        ],
    )