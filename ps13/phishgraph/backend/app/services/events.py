"""Real-time event bus for WebSocket clients (in-process; mirrored through Redis pub/sub when REDIS_URL is set)."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

log = logging.getLogger(__name__)


class EventBus:
    def __init__(self) -> None:
        self.subscribers: set[asyncio.Queue] = set()
        self.recent: list[dict] = []

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self.subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.subscribers.discard(q)

    def publish(self, event: str, data: dict[str, Any]) -> None:
        msg = {'event': event, **data}
        self.recent.append(msg)
        self.recent = self.recent[-200:]
        for q in list(self.subscribers):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass
        try:
            from ..utils.cache import get_cache
            c = get_cache()
            if c.redis:
                c.redis.publish('phishgraph:events', json.dumps(msg, default=str))
        except Exception:
            pass


bus = EventBus()
