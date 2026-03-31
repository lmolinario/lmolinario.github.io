from celery import Celery
from app.core.config import settings


celery = Celery(
    "digital_exposure_worker",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks.scan_tasks"],
)

celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
)