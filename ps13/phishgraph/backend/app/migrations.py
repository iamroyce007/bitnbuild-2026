"""Ordered, idempotent schema migrations tracked in `schema_migrations` (works on PostgreSQL and SQLite)."""
from __future__ import annotations

import logging

from sqlalchemy import inspect, text

log = logging.getLogger(__name__)


def _m0001_initial(conn) -> None:
    from .database import Base
    from .models import database_models  # noqa: F401  (register tables)
    Base.metadata.create_all(conn)


def _m0002_indexes(conn) -> None:
    insp = inspect(conn)
    existing = {i['name'] for i in insp.get_indexes('detections')}
    if 'ix_detections_status_created' not in existing:
        conn.execute(text('CREATE INDEX ix_detections_status_created ON detections (status, created_at)'))


MIGRATIONS = [('0001_initial', _m0001_initial), ('0002_indexes', _m0002_indexes)]


def run(engine) -> list[str]:
    applied = []
    with engine.begin() as conn:
        conn.execute(text('CREATE TABLE IF NOT EXISTS schema_migrations (id VARCHAR(80) PRIMARY KEY, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)'))
        done = {r[0] for r in conn.execute(text('SELECT id FROM schema_migrations'))}
        for mid, fn in MIGRATIONS:
            if mid in done:
                continue
            fn(conn)
            conn.execute(text('INSERT INTO schema_migrations (id) VALUES (:i)'), {'i': mid})
            applied.append(mid)
            log.info('applied migration %s', mid)
    return applied
