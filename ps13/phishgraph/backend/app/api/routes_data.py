"""Read APIs: detections, campaigns, domains, IPs, graph, threat feed, feedback, statistics, model health."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import networkx as nx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, select

from ..database import session_scope
from ..ml.model_registry import all_models
from ..models.database_models import IOC, Campaign, Detection, Domain, Feedback, ResponseAction
from ..models.schemas import FeedbackIn, IOCIn
from ..services import feedback_engine
from ..services.graph_engine import url_node
from ..services.graph_store import get_graph_store
from ..services.intel_store import get_intel_store
from ..services.monitoring import drift_report
from ..services.threat_intel import get_ti
from ..workers.feed_collector import STATUS as FEED_STATUS
from .deps import audit, require_key

router = APIRouter(prefix='/api/v1', tags=['data'])


def _det_summary(d: Detection) -> dict:
    return {'detection_id': d.id, 'kind': d.kind, 'title': d.target, 'risk_score': d.risk_score, 'decision': d.decision, 'scores': d.scores,
            'campaign_id': d.campaign_id, 'status': d.status, 'demo': d.demo, 'conflicting_intelligence': d.conflicting_intelligence,
            'latency_ms': d.latency_ms, 'created_at': d.created_at.isoformat() if d.created_at else None,
            'top_reason': (d.reasons or [{}])[0].get('text') if d.reasons else None, 'channel': (d.report or {}).get('message', {}).get('channel')}


@router.get('/detections')
def detections(limit: int = Query(50, le=500), decision: str | None = None, status: str | None = None, min_risk: float = 0, who: str = Depends(require_key)):
    with session_scope() as s:
        q = select(Detection).where(Detection.risk_score >= min_risk)
        if decision:
            q = q.where(Detection.decision == decision.upper())
        if status:
            q = q.where(Detection.status == status)
        rows = s.execute(q.order_by(desc(Detection.created_at)).limit(limit)).scalars().all()
        return [_det_summary(d) for d in rows]


@router.get('/detection/{det_id}')
def detection(det_id: str, who: str = Depends(require_key)):
    with session_scope() as s:
        d = s.get(Detection, det_id)
        if not d:
            raise HTTPException(404, 'detection not found')
        actions = [{'action': a.action, 'mode': a.mode, 'target': a.target, 'result': a.result, 'at': a.created_at.isoformat()}
                   for a in s.execute(select(ResponseAction).where(ResponseAction.detection_id == det_id).order_by(ResponseAction.created_at)).scalars()]
        fb = [{'label': f.label, 'analyst': f.analyst, 'note': f.note, 'at': f.created_at.isoformat()}
              for f in s.execute(select(Feedback).where(Feedback.detection_id == det_id)).scalars()]
        return {**_det_summary(d), 'report': d.report, 'actions': actions, 'feedback': fb, 'model_versions': d.model_versions}


def _graph_json(g: nx.MultiDiGraph, focus: set[str] | None = None) -> dict:
    nodes = [{'id': n, 'type': d.get('type'), 'label': d.get('label') or n.split(':', 1)[1], 'risk': d.get('risk'), 'malicious': bool(d.get('malicious')),
              'first_seen': d.get('first_seen'), 'last_seen': d.get('last_seen'), 'focus': bool(focus and n in focus),
              **{k: d.get(k) for k in ('asn', 'country', 'age_days', 'registrar', 'tranco_rank') if d.get(k) is not None}} for n, d in g.nodes(data=True)]
    edges = [{'source': a, 'target': b, 'rel': d.get('rel', k), 'first_seen': d.get('first_seen'), 'last_seen': d.get('last_seen'), 'source_system': d.get('source'),
              'confidence': d.get('confidence')} for a, b, k, d in g.edges(keys=True, data=True)]
    return {'nodes': nodes, 'edges': edges}


@router.get('/graph/detection/{det_id}')
def graph_detection(det_id: str, depth: int = Query(3, le=4), who: str = Depends(require_key)):
    g = get_graph_store().subgraph([f'email:{det_id}'], depth=depth, limit=400)
    return _graph_json(g, {f'email:{det_id}'})


@router.get('/graph/domain/{domain}')
def graph_domain(domain: str, depth: int = Query(2, le=4), who: str = Depends(require_key)):
    nid = f'domain:{domain.lower()}'
    g = get_graph_store().subgraph([nid], depth=depth, limit=400)
    if nid not in g:
        raise HTTPException(404, 'domain not in graph')
    return _graph_json(g, {nid})


@router.get('/graph/overview')
def graph_overview(limit: int = Query(350, le=1500), who: str = Depends(require_key)):
    gs = get_graph_store()
    seeds = [c['id'] for c in gs.nodes_by_type('campaign', 40)] + [n['id'] for n in gs.nodes_by_type('email', 60) if (n.get('risk') or 0) >= 30]
    g = gs.subgraph(seeds, depth=3, limit=limit) if seeds else nx.MultiDiGraph()
    return {**_graph_json(g), 'stats': gs.stats()}


@router.get('/domain/{domain}')
def domain_info(domain: str, who: str = Depends(require_key)):
    from ..services.brand_engine import get_brand_engine
    d = domain.lower()
    gs = get_graph_store()
    node = gs.node(f'domain:{d}')
    g = gs.subgraph([f'domain:{d}'], depth=2, limit=200)
    rel = lambda t: sorted({n.split(':', 1)[1] for n, x in g.nodes(data=True) if x.get('type') == t})  # noqa: E731
    bv = get_brand_engine().analyze(d)
    with session_scope() as s:  # recent detections that contained this host
        recent = s.execute(select(Detection).order_by(desc(Detection.created_at)).limit(1000)).scalars().all()
        dets = [_det_summary(x) for x in recent if any(u.get('host') == d for u in (x.report or {}).get('urls', []))][:20]
    return {'domain': d, 'node': node, 'ips': rel('ip'), 'asns': rel('asn'), 'nameservers': rel('ns'), 'certificates': rel('cert'),
            'related_domains': [x for x in rel('domain') if x != d][:40], 'campaigns': rel('campaign'), 'feeds': rel('feed'),
            'brand': {'official': bv.official_brand, 'tranco_rank': bv.tranco_rank, 'findings': [f.__dict__ for f in bv.findings]},
            'local_intel': get_intel_store().match('domain', d), 'detections': dets}


@router.get('/ip/{ip}')
def ip_info(ip: str, who: str = Depends(require_key)):
    gs = get_graph_store()
    g = gs.subgraph([f'ip:{ip}'], depth=2, limit=200)
    return {'ip': ip, 'node': gs.node(f'ip:{ip}'), 'domains': sorted({n.split(':', 1)[1] for n, x in g.nodes(data=True) if x.get('type') == 'domain'}),
            'local_intel': get_intel_store().match('ip', ip)}


@router.get('/campaigns')
def campaigns(limit: int = 50, who: str = Depends(require_key)):
    with session_scope() as s:
        rows = s.execute(select(Campaign).order_by(desc(Campaign.last_seen)).limit(limit)).scalars().all()
        return [{'id': c.id, 'name': c.name, 'risk': c.risk, 'brands': c.brands, 'stats': c.stats, 'first_seen': c.first_seen.isoformat(),
                 'last_seen': c.last_seen.isoformat(), 'demo': c.demo} for c in rows]


@router.get('/campaign/{cid}')
def campaign(cid: str, who: str = Depends(require_key)):
    with session_scope() as s:
        c = s.get(Campaign, cid)
        if not c:
            raise HTTPException(404, 'campaign not found')
        dets = [_det_summary(d) for d in s.execute(select(Detection).where(Detection.campaign_id == cid).order_by(Detection.created_at)).scalars()]
        info = {'id': c.id, 'name': c.name, 'risk': c.risk, 'brands': c.brands, 'stats': c.stats, 'first_seen': c.first_seen.isoformat(),
                'last_seen': c.last_seen.isoformat(), 'demo': c.demo}
    g = get_graph_store().subgraph([f'campaign:{cid}'], depth=4, limit=500)
    return {**info, 'detections': dets, 'graph': _graph_json(g, {f'campaign:{cid}'})}


@router.post('/feedback')
def feedback(body: FeedbackIn, who: str = Depends(require_key)):
    try:
        return feedback_engine.apply(body.detection_id, body.label, analyst=who, note=body.note)
    except KeyError:
        raise HTTPException(404, 'detection not found')


@router.get('/threat-feed')
def threat_feed(limit: int = 100, source: str | None = None, who: str = Depends(require_key)):
    with session_scope() as s:
        q = select(IOC).where(IOC.active.is_(True))
        if source:
            q = q.where(IOC.source == source)
        rows = s.execute(q.order_by(desc(IOC.first_seen)).limit(limit)).scalars().all()
        counts = dict(s.execute(select(IOC.source, func.count()).group_by(IOC.source)).all())
        return {'counts': counts, 'feeds': FEED_STATUS, 'iocs': [{'type': r.ioc_type, 'value': r.value, 'source': r.source, 'tags': r.tags, 'demo': r.demo,
                                                                    'first_seen': r.first_seen.isoformat()} for r in rows]}


@router.post('/threat-feed')
def add_ioc(body: IOCIn, who: str = Depends(require_key)):
    n = get_intel_store().add([(body.ioc_type, body.value.strip())], source='analyst', tags=body.tags)
    if body.ioc_type in ('domain', 'ip'):
        get_graph_store().upsert_node(f'{body.ioc_type}:{body.value.strip().lower()}', body.ioc_type, {'malicious': True, 'risk': 95, 'label': body.value.strip()})
    elif body.ioc_type == 'url':
        get_graph_store().upsert_node(url_node(body.value.strip()), 'url', {'malicious': True, 'risk': 95, 'label': body.value.strip()[:120]})
    audit(who, 'ioc.add', body.value, {'type': body.ioc_type})
    return {'added': n}


@router.get('/statistics')
def statistics(hours: int = 24, who: str = Depends(require_key)):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    with session_scope() as s:
        total = s.execute(select(func.count()).select_from(Detection)).scalar() or 0
        window = s.execute(select(Detection.decision, func.count()).where(Detection.created_at >= since).group_by(Detection.decision)).all()
        lat = s.execute(select(func.avg(Detection.latency_ms)).where(Detection.created_at >= since)).scalar()
        camps = s.execute(select(func.count()).select_from(Campaign)).scalar() or 0
        fb = dict(s.execute(select(Feedback.label, func.count()).group_by(Feedback.label)).all())
        rows = s.execute(select(Detection.created_at, Detection.decision, Detection.risk_score).where(Detection.created_at >= since)).all()
    buckets: dict[str, dict] = {}
    for at, dec, _ in rows:
        k = at.strftime('%H:00') if hours <= 48 else at.strftime('%m-%d')
        b = buckets.setdefault(k, {'t': k, 'ALLOW': 0, 'FLAG': 0, 'QUARANTINE': 0, 'BLOCK': 0})
        b[dec] += 1
    hist = [0] * 10
    for _, _, r in rows:
        hist[min(9, int(r // 10))] += 1
    return {'total_detections': total, 'window_hours': hours, 'by_decision': dict(window), 'avg_latency_ms': round(lat or 0), 'campaigns': camps,
            'feedback': fb, 'timeseries': sorted(buckets.values(), key=lambda b: b['t']), 'risk_histogram': hist, 'graph': get_graph_store().stats(),
            'threat_feed_size': get_intel_store().size()}


@router.get('/providers')
def providers(who: str = Depends(require_key)):
    return {'providers': get_ti().health(), 'feeds': FEED_STATUS}


@router.get('/models')
def models(who: str = Depends(require_key)):
    return {'registry': [{k: v for k, v in m.items() if k != 'report'} | {'splits': m['report'].get('splits'), 'data': m['report'].get('data'),
                                                                          'notes': m['report'].get('notes')} for m in all_models()],
            'training_queue': feedback_engine.training_queue(), 'drift': drift_report()}
