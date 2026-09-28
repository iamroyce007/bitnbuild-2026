"""TTL cache + token-bucket rate limiter + circuit breaker. Redis-backed when REDIS_URL is set, in-process otherwise."""
from __future__ import annotations

import json
import threading
import time
from typing import Any

from ..config import get_settings


class Cache:
    def __init__(self) -> None:
        self._mem: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()
        self.redis = None
        url = get_settings().redis_url
        if url:
            try:
                import redis
                self.redis = redis.Redis.from_url(url, decode_responses=True, socket_timeout=2)
                self.redis.ping()
            except Exception:
                self.redis = None
        self.backend = 'redis' if self.redis else 'memory'

    def get(self, key: str) -> Any | None:
        if self.redis:
            try:
                v = self.redis.get(key)
                return json.loads(v) if v else None
            except Exception:
                return None
        with self._lock:
            hit = self._mem.get(key)
            if not hit:
                return None
            exp, v = hit
            if exp < time.time():
                self._mem.pop(key, None)
                return None
            return json.loads(v)

    def set(self, key: str, value: Any, ttl: int) -> None:
        data = json.dumps(value, default=str)
        if self.redis:
            try:
                self.redis.setex(key, ttl, data)
                return
            except Exception:
                pass
        with self._lock:
            if len(self._mem) > 50_000:
                now = time.time()
                self._mem = {k: v for k, v in self._mem.items() if v[0] > now}
            self._mem[key] = (time.time() + ttl, data)


class RateLimiter:
    """Token bucket per key (e.g. per provider, per API client)."""

    def __init__(self, rate_per_min: float, burst: int | None = None) -> None:
        self.rate = rate_per_min / 60.0
        self.burst = burst or max(1, int(rate_per_min))
        self.state: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str = 'default') -> bool:
        with self._lock:
            now = time.monotonic()
            tokens, last = self.state.get(key, (float(self.burst), now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1:
                self.state[key] = (tokens, now)
                return False
            self.state[key] = (tokens - 1, now)
            return True


class CircuitBreaker:
    """Open after `threshold` consecutive failures; half-open after `cooldown` seconds."""

    def __init__(self, threshold: int = 4, cooldown: float = 120) -> None:
        self.threshold, self.cooldown = threshold, cooldown
        self.failures = 0
        self.opened_at = 0.0
        self.last_error = ''
        self.last_ok = 0.0

    @property
    def state(self) -> str:
        if self.failures < self.threshold:
            return 'closed'
        return 'half-open' if time.time() - self.opened_at > self.cooldown else 'open'

    def allow(self) -> bool:
        return self.state != 'open'

    def ok(self) -> None:
        self.failures = 0
        self.last_ok = time.time()

    def fail(self, err: str) -> None:
        self.failures += 1
        self.last_error = err[:200]
        if self.failures >= self.threshold:
            self.opened_at = time.time()


_cache: Cache | None = None


def get_cache() -> Cache:
    global _cache
    if _cache is None:
        _cache = Cache()
    return _cache
