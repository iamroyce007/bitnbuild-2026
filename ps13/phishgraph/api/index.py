"""Vercel serverless entry point.

Serverless constraints handled here: no persistent disk (SQLite + graph in /tmp, rebuilt on each cold start), no
background workers (jobs run inline), no WebSockets (the dashboard falls back to polling), no PyTorch (the semantic NLP
stage is reported as unavailable). For persistence, set DATABASE_URL to a hosted Postgres.

On a cold start with an empty database:
  1. synchronously (<= 12 s): real, keyless threat feeds OpenPhish + URLhaus -> intel store and threat graph;
  2. in a background thread that keeps going while requests are served: the large keyless domain feeds
     (CERT Polska, Phishing Army, ~280k indicators) and, unless SAMPLE_DATA_ON_START=false, the labelled sample
     data (27 messages marked DEMO DATA, removable from the dashboard) so every page has something to show.
"""
import asyncio
import os
import sys
import threading
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

try:
    from app.services.intel_store import get_intel_store  # noqa: E402
    from app.workers.feed_collector import run_one  # noqa: E402
    fresh = get_intel_store().size() == 0
    if fresh:
        async def _small():
            await asyncio.gather(run_one('openphish'), run_one('urlhaus'))
        asyncio.run(asyncio.wait_for(_small(), timeout=12))
except Exception as e:  # feed down or slow: start anyway, the Intel page shows each collector's status
    fresh = False
    print('feed ingestion skipped:', e)


def _background() -> None:
    try:
        asyncio.run(asyncio.gather(run_one('cert_pl'), run_one('phishing_army')))
    except Exception as e:
        print('large feeds skipped:', e)
    if os.getenv('SAMPLE_DATA_ON_START', 'true').lower() != 'false':
        try:
            from app.services import sample_data
            if not sample_data.status()['loaded']:
                asyncio.run(sample_data.load())
        except Exception as e:
            print('sample data skipped:', e)


if fresh:
    threading.Thread(target=_background, name='cold-start-data', daemon=True).start()

from app.main import app  # noqa: E402,F401
