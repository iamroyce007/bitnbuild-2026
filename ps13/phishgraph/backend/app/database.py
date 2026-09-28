"""SQLAlchemy engine/session. PostgreSQL in production (DATABASE_URL), SQLite locally. Schema changes go
through the ordered migrations in app/migrations.py, tracked in the schema_migrations table."""
from __future__ import annotations

from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


def _make_engine(url: str):
    if url.startswith('postgresql://'):
        url = url.replace('postgresql://', 'postgresql+psycopg://', 1)
    kw = {'pool_pre_ping': True, 'future': True}
    if url.startswith('sqlite'):
        kw['connect_args'] = {'check_same_thread': False, 'timeout': 30}
    else:
        kw.update(pool_size=10, max_overflow=20)
    eng = create_engine(url, **kw)
    if url.startswith('sqlite'):
        @event.listens_for(eng, 'connect')
        def _pragma(conn, _):  # noqa: ANN001
            cur = conn.cursor()
            cur.execute('PRAGMA journal_mode=WAL')
            cur.execute('PRAGMA synchronous=NORMAL')
            cur.close()
    return eng


engine = _make_engine(get_settings().database_url)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope():
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def init_db() -> None:
    from . import migrations
    migrations.run(engine)
