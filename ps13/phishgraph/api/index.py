"""Vercel serverless entry point.

Serverless constraints handled here: no persistent disk (SQLite + graph in /tmp; the public OpenPhish feed is ingested on
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

from app.database import init_db  # noqa: E402

init_db()
# Real intelligence on a fresh instance: pull the public OpenPhish feed (no key needed). Sample data is never loaded
# automatically; the dashboard offers it as an explicit, labelled option.
try:
    from app.services.intel_store import get_intel_store  # noqa: E402
    from app.workers.feed_collector import run_one  # noqa: E402
    if get_intel_store().size() == 0:
        asyncio.run(asyncio.wait_for(run_one('openphish'), timeout=12))
except Exception as e:  # feed down or slow: start anyway, the Intel page shows the collector status
    print('openphish ingestion skipped:', e)

from app.main import app  # noqa: E402,F401
