"""Vercel serverless entry point.

Serverless constraints handled here: no persistent disk (SQLite + graph in /tmp, re-seeded with labelled DEMO DATA on
cold start), no background workers (jobs run inline), no WebSockets (the dashboard falls back to polling), no PyTorch
(the semantic NLP stage is reported as unavailable). For persistence, set DATABASE_URL to a hosted Postgres.
"""
import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault('SERVERLESS', '1')
os.environ.setdefault('DATABASE_URL', 'sqlite:////tmp/phishgraph.db')
os.environ.setdefault('GRAPH_PATH', '/tmp/phishgraph-graph.json')
os.environ.setdefault('ENABLE_EMBEDDINGS', 'false')
os.environ.setdefault('REFERENCE_DIR', str(ROOT / 'data' / 'reference'))
sys.path.insert(0, str(ROOT / 'backend'))
sys.path.insert(0, str(ROOT / 'scripts'))

from app.database import init_db, session_scope  # noqa: E402
from app.models.database_models import Detection  # noqa: E402

init_db()
if os.environ.get('DEMO_MODE', 'true').lower() == 'true':
    with session_scope() as s:
        empty = s.query(Detection).count() == 0
    if empty:
        import seed_demo  # noqa: E402
        seed_demo.seed_feed()
        asyncio.run(seed_demo.replay())

from app.main import app  # noqa: E402,F401
