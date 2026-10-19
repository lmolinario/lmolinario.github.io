"""Administrative funnel statistics are not public report data."""
from secrets import compare_digest

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.services.analytics_service import get_funnel_metrics

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


def require_admin_key(x_admin_key: str | None = Header(default=None)) -> None:
    if not settings.admin_api_key:
        raise HTTPException(status_code=503, detail="Admin API is not configured")
    if not x_admin_key or not compare_digest(x_admin_key, settings.admin_api_key):
        raise HTTPException(status_code=403, detail="Forbidden")


@router.get("/funnel", dependencies=[Depends(require_admin_key)])
def funnel_metrics(db: Session = Depends(get_db)):
    return get_funnel_metrics(db)
