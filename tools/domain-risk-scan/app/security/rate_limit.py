"""Redis-backed, fail-closed rate limit for resource-intensive public scans."""
from datetime import datetime, timezone
from hashlib import sha256

from fastapi import HTTPException, Request
from redis import Redis, RedisError

from app.core.config import settings


def enforce_scan_quota(request: Request) -> None:
    # Do not trust client-supplied X-Forwarded-For headers without a separately
    # configured, verified reverse-proxy trust boundary.
    origin = request.client.host if request.client else "unknown"
    identifier = sha256(origin.encode("utf-8")).hexdigest()[:24]
    hour = datetime.now(timezone.utc).strftime("%Y%m%d%H")
    key = f"scanner:quota:{hour}:{identifier}"
    try:
        redis = Redis.from_url(
            settings.redis_url, socket_connect_timeout=2, socket_timeout=2
        )
        pipe = redis.pipeline(transaction=True)
        pipe.incr(key)
        pipe.expire(key, 7200)
        count, _ = pipe.execute()
        redis.close()
    except RedisError:
        raise HTTPException(status_code=503, detail="Scanner capacity temporarily unavailable")
    if count > settings.scan_rate_limit_per_hour:
        raise HTTPException(
            status_code=429,
            detail="Hourly scan quota exceeded",
            headers={"Retry-After": "3600"},
        )
