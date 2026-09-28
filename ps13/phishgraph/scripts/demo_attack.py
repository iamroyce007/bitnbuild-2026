"""The 3-minute demo, driven through the real API (so the dashboard receives the WebSocket events live).

  1. an email arrives whose URL is on NO threat feed
  2. NLP, URL model and brand engine score it; enrichment + graph run
  3. the graph finds the domain shares IP / nameserver / certificate with known-bad (DEMO DATA) infrastructure
  4. risk fuses, the message is quarantined/blocked, the campaign updates
  5. an analyst confirms -> IOCs enter the local feed
  6. a brand-new variant on yet another domain is caught immediately

Usage: python scripts/demo_attack.py [--api http://localhost:8000] [--key dev-local-key] [--pause 1.5]
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
DATA = json.loads((ROOT / 'data' / 'demo' / 'demo_dataset.json').read_text())
B, R, G, Y, C, D, X = '\033[1m', '\033[31m', '\033[32m', '\033[33m', '\033[36m', '\033[2m', '\033[0m'


def bar(v: float | None) -> str:
    if v is None:
        return f'{D}unavailable{X}'
    n = int(v / 5)
    col = R if v >= 70 else Y if v >= 40 else G
    return f'{col}{"█" * n}{"·" * (20 - n)}{X} {v:5.1f}'


def show(r: dict, pause: float) -> None:
    rep = r['report']
    print(f'\n{B}Scores{X}')
    for k in ('nlp', 'url', 'brand', 'metadata', 'threat_intelligence', 'graph'):
        print(f'  {k:20s} {bar(r["scores"].get(k))}')
        time.sleep(pause / 6)
    print(f'  {"─" * 44}\n  {"FINAL":20s} {bar(r["risk_score"])}   {B}{R if r["decision"] in ("BLOCK", "QUARANTINE") else Y}{r["decision"]}{X}')
    ti = rep['threat_intel']['sources']
    print(f'\n{B}Threat intelligence{X}')
    for s in ti:
        print(f'  {s["source"]:22s} {s["display"]:18s} {D}{(s["summary"] or "")[:70]}{X}')
    if rep['graph']['paths']:
        print(f'\n{B}Graph evidence{X} {D}(data quality: {rep["graph"]["data_quality"]}){X}')
        for p in rep['graph']['paths'][:5]:
            print(f'  {C}•{X} {p["text"]}')
    print(f'\n{B}Why{X}')
    for x in r['reasons'][:9]:
        print(f'  {C}{x["category"]:12s}{X} {x["text"][:100]}')
    if rep.get('overrides'):
        print(f'  {D}overrides: {"; ".join(rep["overrides"])}{X}')
    if r.get('campaign') and r['campaign'].get('id'):
        cm = r['campaign']
        bm = cm.get('best_match') or {}
        print(f'\n{B}Campaign{X} {cm["id"]}  similarity {cm.get("similarity")}  {D}(semantic {bm.get("semantic")}, infrastructure {bm.get("infrastructure")}){X}')
    if rep.get('response'):
        print(f'{B}Response{X} {rep["response"]["action"]} ({rep["response"]["mode"]}): {rep["response"]["result"]}')


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--api', default='http://localhost:8000')
    ap.add_argument('--key', default='dev-local-key')
    ap.add_argument('--pause', type=float, default=1.2)
    a = ap.parse_args()
    c = httpx.Client(base_url=a.api, headers={'X-API-Key': a.key}, timeout=60)
    step = lambda t: (print(f'\n{B}{C}▶ {t}{X}'), time.sleep(a.pause))  # noqa: E731

    m = DATA['live_demo_email']
    step('1. A new email arrives')
    print(f'  From:    {m["sender"]}\n  Subject: {m["subject"]}\n  {D}{m["body"][:160]}...{X}')
    url = 'https://microsoft-login-security.example.xyz/verify'
    feed = c.get('/api/v1/threat-feed', params={'limit': 500}).json()
    listed = any(i['value'].startswith('https://microsoft-login-security') for i in feed['iocs'])
    step(f'2. Is its link on any threat feed? {"yes" if listed else "NO - never seen before"}')
    step('3. Full analysis: NLP + URL model + brand + enrichment + threat intel + graph')
    r = c.post('/api/v1/analyze/email', json={**m, 'deep': True}).json()
    show(r, a.pause)
    step('4. Analyst reviews and confirms phishing')
    fb = c.post('/api/v1/feedback', json={'detection_id': r['detection_id'], 'label': 'confirmed_phishing', 'note': 'demo: confirmed credential harvesting'}).json()
    print(f'  {fb["iocs_added"]} indicator(s) added to the local threat feed; graph nodes marked malicious; sample queued for retraining')
    v = DATA['live_demo_variant']
    step('5. Minutes later: a new variant on a different, never-seen domain')
    print(f'  From:    {v["sender"]}\n  Subject: {v["subject"]}')
    r2 = c.post('/api/v1/analyze/email', json={**v, 'deep': True}).json()
    show(r2, a.pause / 2)
    print(f'\n{B}{G}Done.{X} Open the dashboard to see both detections, the campaign graph and the timeline.\n')


if __name__ == '__main__':
    main()
