"""Optional sample data (DEMO DATA): load on request, remove completely on request.

Nothing here runs automatically in production. The fictional infrastructure (RFC 5737 IPs, RFC 5398 ASNs) is only used
for enrichment while sample data is loaded, so it can never mask a real lookup afterwards.
"""
from __future__ import annotations

import json
from email.message import EmailMessage

import networkx as nx

from ..config import get_settings
from ..database import session_scope
from ..models.database_models import IOC, Campaign, Detection, Email, EmailURL, Feedback, ResponseAction
from .graph_engine import url_node
from .graph_store import get_graph_store
from .intel_store import get_intel_store

_ACTIVE: bool | None = None


def dataset() -> dict:
    return json.loads((get_settings().data_dir / 'demo' / 'demo_dataset.json').read_text())


def active() -> bool:
    """True while sample data is loaded (or DEMO_MODE forces it)."""
    global _ACTIVE
    if get_settings().demo_mode:
        return True
    if _ACTIVE is None:
        with session_scope() as s:
            _ACTIVE = s.query(Detection).filter(Detection.demo.is_(True)).first() is not None
    return _ACTIVE


def status() -> dict:
    with session_scope() as s:
        n = s.query(Detection).filter(Detection.demo.is_(True)).count()
        real = s.query(Detection).filter(Detection.demo.is_(False)).count()
    return {'loaded': n > 0, 'sample_detections': n, 'real_detections': real}


def _seed_feed_and_infrastructure() -> None:
    from ..utils.dns_utils import _demo_enrichment, demo_infrastructure
    from ..utils.url_utils import parse_url
    data = dataset()
    get_intel_store().add([('url', u) for u in data['feed']], source='demo_feed', tags=['phishing', 'DEMO DATA'], demo=True)
    gs = get_graph_store()
    infra = demo_infrastructure()
    gs.upsert_node('feed:demo_feed', 'feed', {'label': 'demo_feed (DEMO DATA)', 'demo': True})
    for u in data['feed']:
        p = parse_url(u)
        e = _demo_enrichment(p.host, infra[p.host])
        uid, did = url_node(p.normalized), f'domain:{p.host}'
        gs.upsert_node(uid, 'url', {'label': p.normalized, 'malicious': True, 'risk': 95, 'demo': True})
        gs.upsert_node(did, 'domain', {'label': p.host, 'malicious': True, 'risk': 95, 'demo': True, 'age_days': e['rdap']['age_days']})
        gs.upsert_edge(uid, 'feed:demo_feed', 'LISTED_IN', source='demo_feed', confidence=0.95)
        gs.upsert_edge(uid, did, 'HOSTED_ON', source='demo_feed')
        ip, asn = e['dns']['a'][0], e['asn'][0]
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


def _to_message(m: dict):
    from .email_parser import parse_json_message, parse_raw_email
    if m.get('attachments'):
        em = EmailMessage()
        em['Subject'], em['From'], em['To'] = m.get('subject', ''), m['sender'], 'you@example.org'
        em.set_content(m.get('body', ''))
        for fn in m['attachments']:
            em.add_attachment(b'<html><form action="https://vendor-payments-desk.xyz/pay"><input type="password"></form></html>', maintype='text', subtype='html', filename=fn)
        return parse_raw_email(em.as_bytes())
    return parse_json_message(subject=m.get('subject', ''), sender=m.get('sender', ''), body=m.get('body', ''), html=m.get('html', ''), channel=m.get('channel', 'email'))


async def load() -> dict:
    """Seed demo feed + infrastructure and replay the sample messages through the real pipeline."""
    global _ACTIVE
    from .pipeline import analyze
    if status()['loaded']:
        return {**status(), 'note': 'sample data already loaded'}
    _ACTIVE = True
    _seed_feed_and_infrastructure()
    data = dataset()
    results = []
    for label, msgs in (('benign', data['benign']), ('phishing', data['phishing'])):
        for m in msgs:
            r = await analyze(_to_message(m), source='sample', deep=True, demo=True)
            results.append((label, r['decision']))
    get_graph_store().save()
    return {**status(), 'benign_allowed': sum(1 for l, d in results if l == 'benign' and d == 'ALLOW'),
            'phishing_caught': sum(1 for l, d in results if l == 'phishing' and d != 'ALLOW')}


def clear() -> dict:
    """Remove every trace of sample data from the database, local feed and graph."""
    global _ACTIVE
    with session_scope() as s:
        ids = [d.id for d in s.query(Detection.id).filter(Detection.demo.is_(True))]
        camp_ids = [c.id for c in s.query(Campaign.id).filter(Campaign.demo.is_(True))]
        for model, col in ((ResponseAction, ResponseAction.detection_id), (Feedback, Feedback.detection_id), (EmailURL, EmailURL.email_id)):
            s.query(model).filter(col.in_(ids)).delete(synchronize_session=False)
        s.query(Detection).filter(Detection.id.in_(ids)).delete(synchronize_session=False)
        s.query(Email).filter(Email.demo.is_(True)).delete(synchronize_session=False)
        s.query(Campaign).filter(Campaign.demo.is_(True)).delete(synchronize_session=False)
        s.query(IOC).filter(IOC.demo.is_(True)).delete(synchronize_session=False)
        # IOCs auto-added when sample messages were blocked or confirmed
        s.query(IOC).filter(IOC.source.in_(['phishgraph_block', 'analyst'])).filter(IOC.value.in_(_sample_urls())).delete(synchronize_session=False)
    gs = get_graph_store()
    g = gs.g if hasattr(gs, 'g') else None
    removed = 0
    if g is not None:
        with gs.lock:
            drop = {n for n, d in g.nodes(data=True) if d.get('demo')} | {f'email:{i}' for i in ids} | {f'campaign:{c}' for c in camp_ids}
            g.remove_nodes_from([n for n in drop if n in g])
            removed = len(drop)
            # prune components that no longer contain a real message or a real feed entry
            for comp in list(nx.weakly_connected_components(g)):
                anchored = any(n.startswith('email:') or n.startswith('feed:') for n in comp)
                if not anchored:
                    g.remove_nodes_from(comp)
                    removed += len(comp)
            gs._dirty += 1
        gs.save()
    get_intel_store().load()
    _ACTIVE = False
    return {**status(), 'graph_nodes_removed': removed}


def _sample_urls() -> list[str]:
    from .url_extractor import extract_urls
    urls = []
    for m in dataset()['benign'] + dataset()['phishing']:
        urls += [e.url.normalized for e in extract_urls(f"{m.get('body', '')} {m.get('html', '')}")]
    return urls
