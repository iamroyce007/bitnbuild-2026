"""In-memory index over the local IOC table (feeds + analyst confirmations + demo seeds).

Matching rules (anti-false-positive):
  exact URL        normalised URL equality
  exact host       the URL's host equals a listed host
  domain-level     the registrable domain is listed as a *domain* IOC, OR a listed URL's registrable domain matches,
                   but never for established (Tranco top-100k) or shared/free-hosting registrable domains:
                   a phishing form on docs.google.com must not taint google.com.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone

from sqlalchemy import select

from ..database import session_scope
from ..models.database_models import IOC
from ..utils.url_utils import parse_url, registrable
from .url_features import FREE_HOSTING


class IntelStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.urls: dict[str, list[dict]] = {}
        self.hosts: dict[str, list[dict]] = {}
        self.domains: dict[str, list[dict]] = {}
        self.ips: dict[str, list[dict]] = {}
        self.hashes: dict[str, list[dict]] = {}
        self.url_regs: dict[str, list[dict]] = {}
        self.loaded = False

    def _shared(self, reg: str) -> bool:
        from .brand_engine import get_brand_engine
        be = get_brand_engine()
        rank = be.rank.get(reg)
        return (rank is not None and rank <= be.established_top) or any(reg == h or reg.endswith('.' + h) for h in FREE_HOSTING) or bool(be.official_brand(reg))

    def _index(self, t: str, v: str, meta: dict) -> None:
        if t == 'url':
            p = parse_url(v)
            if not p:
                return
            self.urls.setdefault(p.normalized, []).append(meta)
            self.hosts.setdefault(p.host, []).append(meta)
            if p.registrable and not self._shared(p.registrable):
                self.url_regs.setdefault(p.registrable, []).append(meta)
        elif t == 'domain':
            self.domains.setdefault(v.lower(), []).append(meta)
        elif t == 'ip':
            self.ips.setdefault(v, []).append(meta)
        elif t == 'hash':
            self.hashes.setdefault(v.lower(), []).append(meta)

    def load(self) -> None:
        with self._lock:
            self.urls, self.hosts, self.domains, self.ips, self.hashes, self.url_regs = {}, {}, {}, {}, {}, {}
            with session_scope() as s:
                for r in s.execute(select(IOC.ioc_type, IOC.value, IOC.source, IOC.demo, IOC.tags, IOC.first_seen).where(IOC.active.is_(True))):
                    self._index(r[0], r[1], {'source': r[2], 'demo': r[3], 'tags': r[4], 'first_seen': r[5].isoformat() if r[5] else None})
            self.loaded = True

    def size(self) -> int:
        return len(self.urls) + len(self.domains) + len(self.ips) + len(self.hashes)

    def match(self, t: str, v: str) -> list[dict]:
        if not self.loaded:
            self.load()
        out = []
        if t == 'url':
            p = parse_url(v)
            if not p:
                return []
            out += [dict(m, match='exact', on=p.normalized) for m in self.urls.get(p.normalized, [])]
            out += [dict(m, match='exact', on=p.host) for m in self.hosts.get(p.host, [])] if not out else []
            t, v = 'domain', p.host
        if t == 'domain':
            h = v.lower()
            reg = registrable(h)
            out += [dict(m, match='exact', on=h) for m in self.domains.get(h, [])]
            if not out and not self._shared(reg):
                out += [dict(m, match='domain', on=reg) for m in self.domains.get(reg, []) + self.url_regs.get(reg, [])]
        elif t == 'ip':
            out += [dict(m, match='exact', on=v) for m in self.ips.get(v, [])]
        elif t == 'hash':
            out += [dict(m, match='exact', on=v) for m in self.hashes.get(v.lower(), [])]
        return out

    def add(self, items: list[tuple[str, str]], source: str, tags: list[str] | None = None, demo: bool = False) -> int:
        """Insert (type, value) IOCs; returns number of new rows."""
        from sqlalchemy.exc import IntegrityError
        n = 0
        now = datetime.now(timezone.utc)
        with session_scope() as s:
            existing = {(r[0], r[1]) for r in s.execute(select(IOC.ioc_type, IOC.value).where(IOC.source == source))}
            for t, v in items:
                if (t, v) in existing:
                    continue
                existing.add((t, v))
                s.add(IOC(ioc_type=t, value=v, source=source, tags=tags or [], demo=demo, first_seen=now, last_seen=now))
                n += 1
            try:
                s.flush()
            except IntegrityError:
                s.rollback()
        with self._lock:
            for t, v in items:
                self._index(t, v, {'source': source, 'demo': demo, 'tags': tags or [], 'first_seen': now.isoformat()})
        return n


_store: IntelStore | None = None


def get_intel_store() -> IntelStore:
    global _store
    if _store is None:
        _store = IntelStore()
    return _store
