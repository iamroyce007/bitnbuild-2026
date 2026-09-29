"""Vercel serverless entry point.

Serverless constraints handled here: no persistent disk (SQLite + graph in /tmp), several instances at once and frozen
between requests (so nothing can be built up in the background), no background workers (jobs run inline), no WebSockets
(the dashboard falls back to polling), no PyTorch (the semantic NLP stage is reported as unavailable).

Every instance starts from the same deploy-time snapshot (scripts/build_snapshot.py, bundled by deploy_vercel.sh):
real OpenPhish + URLhaus indicators and the threat graph they form, the labelled sample data (27 messages marked
DEMO DATA, removable from the dashboard), and ~280k domains from CERT Polska and Phishing Army. On top of that the
instance pulls OpenPhish and URLhaus live (<= 8 s), so the newest phishing is always included.
Set DATABASE_URL to a hosted Postgres for data that persists across instances.
"""
import asyncio
import json
import os
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SNAP = ROOT / 'snapshot'
os.environ.setdefault('SERVERLESS', '1')
os.environ.setdefault('DATABASE_URL', 'sqlite:////tmp/phishgraph.db')
os.environ.setdefault('GRAPH_PATH', '/tmp/phishgraph-graph.json')
os.environ.setdefault('ENABLE_EMBEDDINGS', 'false')
os.environ.setdefault('REFERENCE_DIR', str(ROOT / 'data' / 'reference'))
sys.path.insert(0, str(ROOT / 'backend'))

manifest = {}
if SNAP.exists() and os.environ['DATABASE_URL'] == 'sqlite:////tmp/phishgraph.db' and not Path('/tmp/phishgraph.db').exists():
    shutil.copy(SNAP / 'phishgraph.db', '/tmp/phishgraph.db')
    if (SNAP / 'graph.json').exists():
        shutil.copy(SNAP / 'graph.json', os.environ['GRAPH_PATH'])
    manifest = json.loads((SNAP / 'manifest.json').read_text())

from app.database import init_db  # noqa: E402

init_db()

try:
    from app.services.intel_store import get_intel_store  # noqa: E402
    from app.workers.feed_collector import STATUS, run_one  # noqa: E402
    store = get_intel_store()
    if not manifest and (SNAP / 'manifest.json').exists():  # /tmp db survived from an earlier start of this instance
        manifest = json.loads((SNAP / 'manifest.json').read_text())
    STATUS['snapshot'] = {'status': 'ok' if manifest else 'absent', 'at': time.time(), 'built_at': manifest.get('built_at'),
                          'files': sorted(p.name for p in (SNAP / 'feeds').glob('*')) if (SNAP / 'feeds').exists() else []}
    for name, info in (manifest.get('large_feeds') or {}).items():
        path = SNAP / 'feeds' / f'{name}.txt.gz'
        if info.get('status') == 'ok' and path.exists():
            t = time.time()
            try:
                n = store.load_domain_list(path, name, at=manifest.get('built_at'))
                STATUS[name] = {'status': 'ok', 'mode': f'snapshot {manifest.get("built_at")}', 'fetched': n, 'at': t,
                                'seconds': round(time.time() - t, 1)}
            except Exception as e:
                STATUS[name] = {'status': 'error', 'at': t, 'error': f'{type(e).__name__}: {e}'[:200]}
        else:
            STATUS[name] = {'status': 'missing', 'at': time.time(), 'error': f'snapshot status {info.get("status")}, file present: {path.exists()}'}

    async def _live():
        await asyncio.gather(run_one('openphish'), run_one('urlhaus'))
    asyncio.run(asyncio.wait_for(_live(), timeout=8))
except Exception as e:  # a feed being down or slow never blocks start-up; the Intel page shows each collector's status
    print('live feed refresh skipped:', e)

from app.main import app  # noqa: E402,F401
