"""Common machinery for threat-intelligence providers.

Every provider result states what actually happened (`status`), so the UI can say SOURCE UNAVAILABLE
instead of implying a lookup took place. Privacy rules (enforced in `safe_indicator`):
  * only public indicators (URL, domain, IP, file hash) are ever sent, never message bodies or headers
  * URLs whose query string carries personal data (email addresses, tokens) are reduced to their host
  * private / internal hosts are never sent
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Literal

import httpx

from ..config import get_settings
from ..utils.cache import CircuitBreaker, RateLimiter, get_cache
from ..utils.url_utils import parse_url, ssrf_block_reason

log = logging.getLogger(__name__)
IOCType = Literal['url', 'domain', 'ip', 'hash']
Status = Literal['ok', 'not_configured', 'disabled', 'unavailable', 'error', 'rate_limited', 'circuit_open', 'not_supported', 'skipped_private']


@dataclass
class TIResult:
    source: str
    indicator: str
    ioc_type: str
    status: Status
    verdict: Literal['malicious', 'suspicious', 'clean', 'unknown'] = 'unknown'
    risk: float = 0.0  # 0-100, only meaningful when status == ok
    confidence: float = 0.0  # how much this source's verdict should count (0-1)
    summary: str = ''
    details: dict = field(default_factory=dict)
    relations: list[dict] = field(default_factory=list)  # {rel, type, value} for the graph
    retrieved_at: float = field(default_factory=time.time)
    cached: bool = False
    latency_ms: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


PII_PARAM = re.compile(r'(?:^|&)(?:e?mail|user(?:name)?|login|token|session|sid|key|auth|code|otp|phone|account)=', re.I)
EMAIL_IN_URL = re.compile(r'[a-z0-9._%+-]+(?:@|%40)[a-z0-9.-]+\.[a-z]{2,}', re.I)


def safe_indicator(ioc_type: str, value: str) -> tuple[str, str] | None:
    """Return the indicator that may be sent to a third party, possibly reduced, or None if it must not be sent."""
    if ioc_type == 'url':
        p = parse_url(value)
        if not p or not p.host or ssrf_block_reason(p.host):
            return None
        if PII_PARAM.search(p.query or '') or EMAIL_IN_URL.search(value):
            return ('domain', p.host)  # personal data in the URL: share only the host
        return ('url', p.normalized)
    if ioc_type in ('domain', 'ip'):
        return None if ssrf_block_reason(value) else (ioc_type, value.lower())
    return (ioc_type, value)


class Connector:
    name = 'base'
    supports: tuple[str, ...] = ()
    key_setting: str | None = None
    ttl = 6 * 3600
    rate_per_min = 30
    external = True  # talks to a third party

    def __init__(self) -> None:
        self.breaker = CircuitBreaker()
        self.limiter = RateLimiter(self.rate_per_min, burst=max(2, self.rate_per_min // 4))
        self.calls = 0
        self.errors = 0
        self.latency_ms_total = 0

    @property
    def api_key(self) -> str:
        return getattr(get_settings(), self.key_setting, '') if self.key_setting else ''

    @property
    def configured(self) -> bool:
        return not self.key_setting or bool(self.api_key)

    @property
    def enabled(self) -> bool:
        return self.configured and (get_settings().enable_external_ti or not self.external)

    def health(self) -> dict:
        state = 'not_configured' if not self.configured else 'disabled' if not self.enabled else {'closed': 'online', 'half-open': 'degraded', 'open': 'offline'}[self.breaker.state]
        return {'name': self.name, 'state': state, 'configured': self.configured, 'enabled': self.enabled, 'external': self.external,
                'calls': self.calls, 'errors': self.errors, 'avg_latency_ms': round(self.latency_ms_total / self.calls) if self.calls else None,
                'last_error': self.breaker.last_error or None, 'last_ok': self.breaker.last_ok or None, 'supports': list(self.supports)}

    def _res(self, ioc_type: str, value: str, status: Status, **kw) -> TIResult:
        return TIResult(self.name, value, ioc_type, status, **kw)

    async def lookup(self, ioc_type: str, value: str) -> TIResult:
        if ioc_type not in self.supports:
            return self._res(ioc_type, value, 'not_supported')
        if not self.configured:
            return self._res(ioc_type, value, 'not_configured', summary=f'{self.name} API key not set')
        if not self.enabled:
            return self._res(ioc_type, value, 'disabled', summary='external threat intelligence disabled (ENABLE_EXTERNAL_TI=false)')
        if self.external:
            safe = safe_indicator(ioc_type, value)
            if safe is None:
                return self._res(ioc_type, value, 'skipped_private', summary='indicator is private/internal; not sent to a third party')
            ioc_type, value = safe
            if ioc_type not in self.supports:
                return self._res(ioc_type, value, 'not_supported')
        ck = f'ti:{self.name}:{ioc_type}:{hashlib.sha256(value.encode()).hexdigest()[:24]}'
        hit = get_cache().get(ck)
        if hit:
            r = TIResult(**hit)
            r.cached = True
            return r
        if not self.breaker.allow():
            return self._res(ioc_type, value, 'circuit_open', summary=f'{self.name} temporarily disabled after repeated failures')
        if not self.limiter.allow():
            return self._res(ioc_type, value, 'rate_limited', summary=f'{self.name} local rate limit reached')
        t0 = time.monotonic()
        delay = 0.5
        for attempt in range(3):
            try:
                self.calls += 1
                r = await asyncio.wait_for(self._lookup(ioc_type, value), timeout=get_settings().ti_timeout_s)
                r.latency_ms = int((time.monotonic() - t0) * 1000)
                self.latency_ms_total += r.latency_ms
                self.breaker.ok()
                if r.status == 'ok':
                    get_cache().set(ck, r.to_dict(), self.ttl)
                return r
            except httpx.HTTPStatusError as e:
                code = e.response.status_code
                if code == 429 or code >= 500:
                    await asyncio.sleep(delay)
                    delay *= 2
                    last = f'HTTP {code}'
                    continue
                self.errors += 1
                self.breaker.fail(f'HTTP {code}')
                return self._res(ioc_type, value, 'error', summary=f'{self.name} HTTP {code}')
            except Exception as e:  # timeout / network
                last = type(e).__name__
                await asyncio.sleep(delay)
                delay *= 2
        self.errors += 1
        self.breaker.fail(last)
        return self._res(ioc_type, value, 'unavailable', summary=f'{self.name} unavailable ({last})')

    async def _lookup(self, ioc_type: str, value: str) -> TIResult:  # pragma: no cover - implemented by providers
        raise NotImplementedError

    @staticmethod
    def client(**kw) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=get_settings().ti_timeout_s, headers={'user-agent': 'PhishGraph/1.0 (+security research)'} | kw.pop('headers', {}), **kw)
