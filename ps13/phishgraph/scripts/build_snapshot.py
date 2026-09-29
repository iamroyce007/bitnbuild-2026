"""Build the deploy-time data snapshot for the serverless demo.

Serverless instances start empty, run several at once, and are frozen between requests, so data cannot be built up in
the background. Instead, `scripts/deploy_vercel.sh` runs this once per deploy and bundles the result; every instance
copies it to /tmp in about a second (api/index.py), then still pulls OpenPhish and URLhaus live on top.

    python scripts/build_snapshot.py        -> snapshot/ (git-ignored)

Contents: a SQLite database with the real OpenPhish + URLhaus indicators and the labelled sample data (27 messages,
DEMO DATA), the threat graph built from both, and the large keyless domain feeds (CERT Polska, Phishing Army) as
compressed lists, already filtered so no top-100k site, official brand domain or hosting-platform root is included.
"""
from __future__ import annotations

import asyncio
import gzip
import json
import os
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'snapshot'


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    (OUT / 'feeds').mkdir(parents=True)
    os.environ.update({'DATABASE_URL': f'sqlite:///{OUT / "phishgraph.db"}', 'GRAPH_PATH': str(OUT / 'graph.json'),
                       'ENABLE_EMBEDDINGS': 'false', 'SERVERLESS': '1', 'REFERENCE_DIR': str(ROOT / 'data' / 'reference')})
    sys.path.insert(0, str(ROOT / 'backend'))
    from app.database import init_db
    init_db()
    from app.services import sample_data
    from app.services.intel_store import get_intel_store
    from app.workers.feed_collector import _domains, _get, run_one

    t0 = time.time()
    small = {k: asyncio.run(run_one(k)) for k in ('openphish', 'urlhaus')}
    sample = asyncio.run(sample_data.load())
    store = get_intel_store()
    feeds = {}
    for name, url in (('cert_pl', 'https://hole.cert.pl/domains/v2/domains.txt'),
                      ('phishing_army', 'https://phishing.army/download/phishing_army_blocklist.txt')):
        try:
            doms = sorted({d for d in _domains(asyncio.run(_get(url)).text) if not store._shared_root(d)})
        except Exception as e:  # a feed being down must not block a deploy; the Intel page shows it
            feeds[name] = {'status': 'error', 'error': str(e)[:200]}
            continue
        with gzip.open(OUT / 'feeds' / f'{name}.txt.gz', 'wt', encoding='utf-8') as f:
            f.write('\n'.join(doms))
        feeds[name] = {'status': 'ok', 'fetched': len(doms)}
    from app.services.graph_store import get_graph_store
    get_graph_store().save()
    manifest = {'built_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'seconds': round(time.time() - t0, 1),
                'small_feeds': {k: {x: v.get(x) for x in ('status', 'fetched')} for k, v in small.items()},
                'large_feeds': feeds, 'sample': sample, 'graph': get_graph_store().stats()}
    (OUT / 'manifest.json').write_text(json.dumps(manifest, indent=1))
    size = sum(p.stat().st_size for p in OUT.rglob('*') if p.is_file())
    print(json.dumps(manifest, indent=1), f'\nsnapshot: {size / 1e6:.1f} MB in {OUT}')


if __name__ == '__main__':
    main()
