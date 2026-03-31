from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services.analytics_service import get_funnel_metrics

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


@router.get("/funnel")
def funnel_metrics(db: Session = Depends(get_db)):
    return get_funnel_metrics(db)