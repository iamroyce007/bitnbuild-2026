"""Seed the DEMO DATA: demo threat-feed IOCs, their (fictional) infrastructure in the graph, and a replay of
12 benign + 15 phishing messages through the real pipeline so detections and campaigns exist.

Usage:  python scripts/seed_demo.py [--reset]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import Counter
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))

from app.config import get_settings  # noqa: E402
from app.database import engine, init_db, session_scope  # noqa: E402
from app.models.database_models import IOC, AuditLog, Campaign, Detection, Email, EmailURL, Feedback, ResponseAction, URLRecord  # noqa: E402
from app.services.email_parser import parse_json_message, parse_raw_email  # noqa: E402
from app.services.graph_engine import url_node  # noqa: E402
from app.services.graph_store import get_graph_store  # noqa: E402
from app.services.intel_store import get_intel_store  # noqa: E402
from app.services.pipeline import analyze  # noqa: E402
from app.utils.dns_utils import _demo_enrichment, demo_infrastructure  # noqa: E402
from app.utils.url_utils import parse_url  # noqa: E402

DATA = json.loads((ROOT / 'data' / 'demo' / 'demo_dataset.json').read_text())


def reset() -> None:
    with session_scope() as s:
        for m in (ResponseAction, Feedback, EmailURL, Detection, Email, URLRecord, Campaign, AuditLog):
            s.query(m).delete()
        s.query(IOC).filter(IOC.source.in_(['demo_feed', 'phishgraph_block', 'analyst'])).delete(synchronize_session=False)
    get_graph_store().clear()
    get_intel_store().load()
    print('reset: detections, campaigns, demo IOCs and graph cleared')


def seed_feed() -> None:
    n = get_intel_store().add([('url', u) for u in DATA['feed']], source='demo_feed', tags=['phishing', 'DEMO DATA'], demo=True)
    gs = get_graph_store()
    infra = demo_infrastructure()
    for u in DATA['feed']:
        p = parse_url(u)
        e = _demo_enrichment(p.host, infra[p.host])
        uid, did = url_node(p.normalized), f'domain:{p.host}'
        gs.upsert_node('feed:demo_feed', 'feed', {'label': 'demo_feed (DEMO DATA)'})
        gs.upsert_node(uid, 'url', {'label': p.normalized, 'malicious': True, 'risk': 95, 'demo': True})
        gs.upsert_node(did, 'domain', {'label': p.host, 'malicious': True, 'risk': 95, 'demo': True, 'age_days': e['rdap']['age_days']})
        gs.upsert_edge(uid, 'feed:demo_feed', 'LISTED_IN', source='demo_feed', confidence=0.95)
        gs.upsert_edge(uid, did, 'HOSTED_ON', source='demo_feed')
        ip = e['dns']['a'][0]
        asn = e['asn'][0]
        gs.upsert_node(f'ip:{ip}', 'ip', {'label': ip, 'asn': asn['asn'], 'demo': True})
        gs.upsert_edge(did, f'ip:{ip}', 'RESOLVES_TO', source='DEMO DATA')
        gs.upsert_node(f'asn:{asn["asn"]}', 'asn', {'label': f'{asn["asn"]} {asn["name"]}', 'demo': True})
        gs.upsert_edge(f'ip:{ip}', f'asn:{asn["asn"]}', 'BELONGS_TO', source='DEMO DATA')
        for ns in e['dns']['ns']:
            gs.upsert_node(f'ns:{ns}', 'ns', {'label': ns, 'demo': True})
            gs.upsert_edge(did, f'ns:{ns}', 'USES_NS', source='DEMO DATA')
        cid = f'cert:{e["tls"]["sha256"][:32]}'
        gs.upsert_node(cid, 'cert', {'label': 'CN=Demo Free CA', 'demo': True})
        gs.upsert_edge(did, cid, 'USES_CERT', source='DEMO DATA')
    gs.save()
    print(f'demo feed: {len(DATA["feed"])} IOCs ({n} new) + infrastructure seeded in the graph')


def to_message(m: dict):
    if m.get('attachments'):
        em = EmailMessage()
        em['Subject'], em['From'], em['To'] = m.get('subject', ''), m['sender'], 'you@example.org'
        em.set_content(m.get('body', ''))
        for fn in m['attachments']:
            em.add_attachment(b'<html><form action="https://vendor-payments-desk.xyz/pay"><input type="password"></form></html>', maintype='text', subtype='html', filename=fn)
        return parse_raw_email(em.as_bytes())
    pm = parse_json_message(subject=m.get('subject', ''), sender=m.get('sender', ''), body=m.get('body', ''), html=m.get('html', ''), channel=m.get('channel', 'email'))
    return pm


async def replay() -> None:
    res = []
    for label, msgs in (('benign', DATA['benign']), ('phishing', DATA['phishing'])):
        for m in msgs:
            r = await analyze(to_message(m), source='demo', deep=True, demo=True)
            res.append((label, r))
            print(f'  [{label:8s}] {r["risk_score"]:5.1f} {r["decision"]:10s} {r["title"][:70]}' + (f'  -> {r["campaign"]["id"]}' if r.get('campaign') and r['campaign'].get('id') else ''))
    get_graph_store().save()
    ok_b = sum(1 for l, r in res if l == 'benign' and r['decision'] == 'ALLOW')
    ok_p = sum(1 for l, r in res if l == 'phishing' and r['decision'] != 'ALLOW')
    print(f'\nbenign allowed: {ok_b}/{len(DATA["benign"])}   phishing caught (FLAG or higher): {ok_p}/{len(DATA["phishing"])}')
    print('decisions:', dict(Counter(r['decision'] for _, r in res)))
    with session_scope() as s:
        for c in s.query(Campaign).all():
            print(f'  {c.id}  {c.name:45s} emails={c.stats.get("emails")} domains={c.stats.get("domains")} ips={c.stats.get("ips")}')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--reset', action='store_true')
    a = ap.parse_args()
    if not get_settings().demo_mode:
        sys.exit('DEMO_MODE is false; refusing to seed demo data')
    init_db()
    if a.reset:
        reset()
    seed_feed()
    asyncio.run(replay())
