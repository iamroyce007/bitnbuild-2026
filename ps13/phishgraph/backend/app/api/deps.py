"""Authentication (X-API-Key), per-client rate limiting, audit logging, request metrics."""
from __future__ import annotations

import hashlib
import hmac
import time
from collections import defaultdict

from fastapi import Header, HTTPException, Request

from ..config import get_settings
from ..database import session_scope
from ..models.database_models import AuditLog, User
from ..utils.cache import RateLimiter

_limiter: RateLimiter | None = None
METRICS: dict = {'requests': defaultdict(int), 'errors': defaultdict(int), 'latency_ms_sum': defaultdict(float), 'detections': defaultdict(int),
                 'inference_ms_sum': 0.0, 'inference_count': 0, 'started': time.time()}


def _hash(k: str) -> str:
    return hashlib.sha256(k.encode()).hexdigest()


def client_for(key: str) -> str | None:
    s = get_settings()
    for k in s.api_key_set:
        if hmac.compare_digest(k, key):
            return 'env-key'
    with session_scope() as ses:
        u = ses.query(User).filter_by(api_key_hash=_hash(key)).one_or_none()
        return u.name if u else None


async def require_key(request: Request, x_api_key: str | None = Header(None, alias='X-API-Key')) -> str:
    global _limiter
    key = x_api_key or request.query_params.get('api_key')
    who = client_for(key) if key else None
    if not who:
        raise HTTPException(401, 'missing or invalid API key (send X-API-Key)')
    if _limiter is None:
        _limiter = RateLimiter(get_settings().rate_limit_per_minute, burst=max(20, get_settings().rate_limit_per_minute // 6))
    if not _limiter.allow(_hash(key)[:16]):
        raise HTTPException(429, 'rate limit exceeded')
    request.state.client = who
    return who


def audit(actor: str, action: str, target: str = '', detail: dict | None = None, ip: str = '') -> None:
    with session_scope() as s:
        s.add(AuditLog(actor=actor, action=action, target=target[:500], detail=detail or {}, ip=ip))
