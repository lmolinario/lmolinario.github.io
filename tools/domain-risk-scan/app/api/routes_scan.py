from fastapi import APIRouter, Depends, HTTPException, Request
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
    update_scan_failed,
    get_findings_by_scan,
    get_recent_completed_scan_by_domain,
)
from app.tasks.scan_tasks import run_scan_task
from app.utils.validators import normalize_domain, is_valid_domain, is_safe_external_domain
from app.security.rate_limit import enforce_scan_quota
from app.security.scan_access import mint_scan_token, require_owned_scan, scan_token_header

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanCreateResponse)
def create_scan_endpoint(payload: ScanCreate, request: Request, db: Session = Depends(get_db)):
    domain = normalize_domain(payload.domain)

    if not is_valid_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain")
    if not is_safe_external_domain(domain):
        raise HTTPException(status_code=400, detail="Domain does not resolve exclusively to public addresses")

    enforce_scan_quota(request)

    # Every request gets its own unguessable credential. No cross-user cached IDs.
    scan = create_scan(db, domain)
    scan_token = mint_scan_token(db, scan.id)
    try:
        run_scan_task.delay(scan.id)
    except Exception:
        update_scan_failed(db, scan, "Background queue unavailable")
        raise HTTPException(status_code=503, detail="Scanner queue temporarily unavailable")

    return ScanCreateResponse(
        scan_id=scan.id,
        status=scan.status,
        scan_token=scan_token,
        cached=False,
    )


@router.get("/{scan_id}", response_model=ScanStatusResponse)
def get_scan_endpoint(scan_id: int, token: str | None = Depends(scan_token_header), db: Session = Depends(get_db)):
    scan = require_owned_scan(db, scan_id, token)

    return ScanStatusResponse(
        scan_id=scan.id,
        domain=scan.domain,
        status=scan.status,
        score=scan.score,
        summary=scan.summary_json,
        risk_level=_score_to_risk_level(scan.score),
    )


@router.get("/{scan_id}/findings", response_model=FindingsListResponse)
def get_scan_findings_endpoint(scan_id: int, token: str | None = Depends(scan_token_header), db: Session = Depends(get_db)):
    scan = require_owned_scan(db, scan_id, token)

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