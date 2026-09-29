"""Real-world check: hundreds of real URLs through the full detection pipeline, with the threat feeds switched OFF so
the engines (NLP/URL model/brand/look-alike/sender/graph fusion) must decide on their own.

    python scripts/real_world_check.py [--phish 200] [--longtail 200] [--top 60]

Sets (all real, fetched or read at run time):
  phishing   today's OpenPhish feed (live, unseen by the models; the local intel store is empty in this run, so a feed
             listing cannot give the answer away)
  long tail  random Tranco sites ranked 150,001 - 1,000,000: ordinary real sites outside every protected, trained and
             evaluated range. Flagging them is a false alarm.
  top sites  random Tranco top-10,000 sites: must be ALLOWed.
Fast path (no DNS/RDAP/TLS), the same path the dashboard's first answer uses. Recorded in the testing history.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import random
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = Path(tempfile.mkdtemp(prefix='pg-realworld-'))
os.environ.update({'DATABASE_URL': f'sqlite:///{TMP / "t.db"}', 'GRAPH_PATH': str(TMP / 'g.json'), 'ENABLE_ACTIVE_ENRICHMENT': 'false',
                   'ENABLE_EXTERNAL_TI': 'false', 'SERVERLESS': '1', 'REFERENCE_DIR': str(ROOT / 'data' / 'reference')})
sys.path.insert(0, str(ROOT / 'backend'))

import httpx  # noqa: E402

RANK = {'ALLOW': 0, 'FLAG': 1, 'QUARANTINE': 2, 'BLOCK': 3}


def tranco(lo: int, hi: int, n: int, rng: random.Random) -> list[str]:
    lines = []
    for name in ('raw/top-1m.csv', 'reference/top-1m.csv'):
        p = ROOT / 'data' / name
        if p.exists():
            lines = p.read_text().splitlines()
            break
    pool = [l.split(',', 1)[1].strip() for l in lines[lo:hi] if ',' in l]
    return [f'https://{d}/' for d in rng.sample(pool, min(n, len(pool)))]


async def run(urls: list[str]) -> list[dict]:
    from app.services.email_parser import ParsedMessage
    from app.services.pipeline import analyze
    from app.services.url_extractor import ExtractedURL
    from app.utils.url_utils import parse_url
    out = []
    for u in urls:
        p = parse_url(u)
        if not p or not p.host:
            continue
        r = await analyze(ParsedMessage(channel='url', text='', urls=[ExtractedURL(p, ['api'])]), source='real_world', kind='url', persist=False)
        top = r['reasons'][0]['text'] if r['reasons'] else ''
        out.append({'url': u, 'decision': r['decision'], 'risk': r['risk_score'], 'reason': top[:140]})
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--phish', type=int, default=200)
    ap.add_argument('--longtail', type=int, default=200)
    ap.add_argument('--top', type=int, default=60)
    ap.add_argument('--seed', type=int, default=int(time.strftime('%Y%m%d')))
    ap.add_argument('--no-record', action='store_true')
    a = ap.parse_args()
    rng = random.Random(a.seed)
    from app.database import init_db
    init_db()

    feed = httpx.get('https://openphish.com/feed.txt', timeout=30, follow_redirects=True, headers={'User-Agent': 'PhishGraph-eval/1.0'}).text.split()
    phish = [u for u in dict.fromkeys(feed) if u.startswith('http')]
    phish = rng.sample(phish, min(a.phish, len(phish)))
    longtail = tranco(150_000, 1_000_000, a.longtail, rng)
    top = tranco(0, 10_000, a.top, rng)

    t0 = time.time()
    res = {name: asyncio.run(run(urls)) for name, urls in (('phishing', phish), ('longtail', longtail), ('top', top))}
    secs = round(time.time() - t0, 1)

    def rate(rows, pred):
        return round(sum(1 for r in rows if pred(r)) / max(1, len(rows)), 4)
    flagged = lambda r: RANK[r['decision']] >= 1
    strong = lambda r: RANK[r['decision']] >= 2
    summary = {
        'n_total': sum(len(v) for v in res.values()), 'n_phishing': len(res['phishing']), 'n_longtail': len(res['longtail']), 'n_top': len(res['top']),
        'phishing_flagged': rate(res['phishing'], flagged), 'phishing_quarantine_or_block': rate(res['phishing'], strong),
        'longtail_false_alarm': rate(res['longtail'], flagged), 'longtail_quarantine_or_block': rate(res['longtail'], strong),
        'top_false_alarm': rate(res['top'], flagged), 'feeds': 'off (engines only)', 'seconds': secs, 'seed': a.seed,
    }
    print(f"\n{summary['n_total']} real URLs in {secs}s (threat feeds OFF: engines only)")
    print(f"  live phishing (OpenPhish, n={summary['n_phishing']}):  flagged {summary['phishing_flagged']:.1%}, quarantine/block {summary['phishing_quarantine_or_block']:.1%}")
    print(f"  long-tail real sites (n={summary['n_longtail']}):     false alarm {summary['longtail_false_alarm']:.1%}, quarantine/block {summary['longtail_quarantine_or_block']:.1%}")
    print(f"  top-10k sites (n={summary['n_top']}):                 false alarm {summary['top_false_alarm']:.1%}")
    for name in ('phishing', 'longtail', 'top'):
        wrong = [r for r in res[name] if (not flagged(r)) == (name == 'phishing')]
        print(f"  {name} errors (sample):", [(r['url'][:60], r['decision'], round(r['risk'])) for r in wrong[:6]])
    out = ROOT / 'data' / 'processed' / 'real_world_check.json'
    import json
    out.write_text(json.dumps({'summary': summary, 'results': res}, indent=1))
    if not a.no_record:
        from app.services import validation_log
        rows = [{'area': k, 'check': r['url'], 'ok': (flagged(r) if k == 'phishing' else not flagged(r)), 'detail': f"{r['decision']} {round(r['risk'])} {r['reason']}", 'ms': None}
                for k, v in res.items() for r in v]
        validation_log.append('real_world', summary, {'rows': rows}, target='pipeline, feeds off')


if __name__ == '__main__':
    main()
