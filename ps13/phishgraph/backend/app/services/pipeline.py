"""The detection pipeline: ingestion -> parallel analysis -> fusion -> explanation -> decision -> graph/campaign -> response -> event.

Fast path (synchronous API): NLP, URL ML + rules, brand/look-alike, metadata, local threat feeds, graph built from
what is already known. Deep path (background or ?deep=true): DNS/RDAP/TLS/ASN enrichment and external threat
intelligence, after which the detection is re-scored and a `detection_updated` event is emitted.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone

from ..config import get_settings
from ..database import session_scope
from ..ml.model_registry import active
from ..models.database_models import Detection, Email, EmailURL, URLRecord
from ..utils.dns_utils import enrich_host
from . import campaign_engine, graph_engine, metadata_engine
from .email_parser import ParsedMessage
from .events import bus
from .explainability import build_report
from .nlp_engine import get_nlp_engine
from .response_engine import respond
from .risk_engine import fuse
from .threat_intel import get_ti
from .url_engine import URLResult, get_url_engine

log = logging.getLogger(__name__)


def _model_versions() -> dict:
    out = {}
    for n in ('url', 'email'):
        m = active(n)
        out[n] = f'v{m["version"]}' if m else 'missing'
    return out


def _iocs(url_results: list[URLResult], pm: ParsedMessage) -> list[tuple[str, str]]:
    iocs: list[tuple[str, str]] = []
    for u in url_results:
        if u.trusted and not u.rules:
            continue  # never spend third-party lookups (or leak) links to established sites
        iocs.append(('url', u.parsed.normalized))
        if u.parsed.host:
            iocs.append(('domain', u.parsed.host))
    if pm.sender_domain:
        iocs.append(('domain', pm.sender_domain))
    for a in pm.attachments:
        iocs.append(('hash', a.sha256))
    return iocs


async def _deep(url_results: list[URLResult], pm: ParsedMessage) -> tuple[dict, object]:
    hosts = list(dict.fromkeys(u.parsed.host for u in url_results if u.parsed.host and not (u.trusted and not u.rules)))[:6]
    enrich_task = asyncio.gather(*(enrich_host(h) for h in hosts)) if hosts else asyncio.sleep(0, result=[])
    ti_task = get_ti().lookup_many(_iocs(url_results, pm))
    enr, ti = await asyncio.gather(enrich_task, ti_task)
    ips = {ip for e in enr for ip in (e.get('dns') or {}).get('a', [])[:2]}
    if ips:  # IP reputation needs resolved IPs
        extra = await get_ti().lookup_many([('ip', ip) for ip in list(ips)[:4]])
        ti.results += extra.results
        ti.hits += extra.hits
        ti.sources_ok = sorted(set(ti.sources_ok) | set(extra.sources_ok))
        if extra.hits:
            acc = (1 - ti.score / 100)
            for r in extra.hits:
                acc *= 1 - (r.risk / 100) * r.confidence
            ti.score = round(100 * (1 - acc), 1)
    return {e['host']: e for e in enr}, ti


def _domain_age_rule(enrichment: dict) -> list[dict]:
    out = []
    for host, e in enrichment.items():
        age = (e.get('rdap') or {}).get('age_days')
        if age is not None and age <= 30:
            out.append({'id': 'new_domain', 'label': f'{e.get("registrable", host)} was registered only {age} day(s) ago', 'weight': 0.35 if age <= 7 else 0.22})
        tls = e.get('tls') or {}
        if tls.get('age_days') is not None and tls['age_days'] <= 3:
            out.append({'id': 'fresh_cert', 'label': f'TLS certificate for {host} issued {tls["age_days"]} day(s) ago', 'weight': 0.1})
    return out


async def analyze(pm: ParsedMessage, *, source: str = 'api', deep: bool = False, demo: bool = False, persist: bool = True,
                  detection_id: str | None = None, kind: str = 'email') -> dict:
    t0 = time.perf_counter()
    s = get_settings()
    det_id = detection_id or str(uuid.uuid4())
    ue = get_url_engine()
    url_results: list[URLResult] = []
    for ex in pm.urls[:15]:
        r = ue.analyze(ex.url, ex.sources, ex.deceptive_text)
        if r:
            url_results.append(r)
    has_text = len(pm.text.strip()) >= 12 and kind != 'url'
    nlp = await asyncio.to_thread(get_nlp_engine().analyze, pm.text) if has_text else None
    meta = metadata_engine.analyze(pm)

    enrichment: dict = {}
    if deep:
        enrichment, ti = await _deep(url_results, pm)
    else:
        ti = await get_ti().lookup_many([i for i in _iocs(url_results, pm)])  # local feeds answer instantly; external only if enabled
    extra_rules = _domain_age_rule(enrichment)

    seeds = graph_engine.ingest(det_id, pm, url_results, enrichment, ti.results, demo=demo)
    brands = sorted({u.brand.findings[0].brand for u in url_results if u.brand and u.brand.findings and u.brand.findings[0].brand} | set(meta.claimed_brands))
    best_camp, camp_sim = campaign_engine.match(nlp.embedding if nlp else None, seeds, brands) if seeds or nlp else (None, 0.0)
    gr = graph_engine.score(seeds, exclude=f'email:{det_id}', campaign_similarity=camp_sim)

    url_score = max((u.score for u in url_results), default=None)
    if extra_rules and url_score is not None:
        acc = 1 - url_score / 100
        for r in extra_rules:
            acc *= 1 - r['weight']
        url_score = round(100 * (1 - acc), 1)
    brand_conf = max([u.brand.score for u in url_results if u.brand] + [max((x['weight'] for x in meta.signals if x['id'] == 'sender_lookalike'), default=0)], default=0)
    brand_score = round(100 * brand_conf, 1) if (url_results or pm.sender_domain) else None
    graph_score = gr.score if gr.data_quality != 'limited' else None  # too little graph context is 'unavailable', not 'safe'
    ti_score = ti.score if ti.available else None
    hard_bad = any(r.source == 'local_intel' and r.risk >= 95 for r in ti.hits) or any(r.verdict == 'malicious' and r.confidence >= 0.9 for r in ti.hits)
    strong_brand = any(u.brand and u.brand.findings and (u.brand.findings[0].kind in ('homograph', 'substitution', 'subdomain_spoof')
                                                         or (u.brand.findings[0].confidence >= 0.84 and nlp is not None and nlp.score >= 60))
                       for u in url_results)
    all_trusted = bool(url_results) and all(u.trusted for u in url_results)
    families = sum([
        bool(nlp and nlp.score >= 40 and nlp.intents),            # language: concrete scam intent, not just a model score
        bool(url_score is not None and url_score >= 50 and any(u.rules for u in url_results)),  # link: rule evidence
        bool(brand_score and brand_score >= 60),                  # brand impersonation
        bool(meta.score >= 40),                                   # sender / headers / attachments / evasion
        bool(ti_score is not None and ti_score >= 50),            # threat intelligence
        bool(graph_score is not None and graph_score >= 40),      # infrastructure graph
    ])
    fusion = fuse(nlp.score if nlp else None, url_score, ti_score, graph_score, brand_score, meta.score,
                  hard_known_bad=hard_bad, strong_brand=strong_brand, all_urls_trusted=all_trusted, ti_clean_votes=ti.clean_votes,
                  evasion=bool(pm.tricks), families=families, trust=meta.trust)

    campaign_id = None
    if fusion.decision != 'ALLOW':
        intents = [i.id for i in nlp.intents] if nlp else []
        campaign_id = await asyncio.to_thread(campaign_engine.assign, det_id, nlp.embedding if nlp else None, seeds, brands, intents,
                                              fusion.final, best_camp, camp_sim, demo)
    get_graph_store_node_risk(det_id, url_results, fusion.final)
    latency = int((time.perf_counter() - t0) * 1000)
    report = build_report(det_id, pm, nlp, url_results, meta, ti, gr, fusion, enrichment, extra_rules, best_camp, camp_sim, campaign_id,
                          deep=deep, latency_ms=latency, demo=demo)
    if persist:
        await asyncio.to_thread(_persist, det_id, pm, url_results, report, fusion, campaign_id, latency, source, demo, kind)
        action = await asyncio.to_thread(respond, det_id, fusion.decision, pm, source)
        report['response'] = action
        bus.publish('new_detection', {'detection_id': det_id, 'risk': fusion.final, 'decision': fusion.decision, 'kind': kind,
                                      'title': report['title'], 'campaign_id': campaign_id, 'demo': demo,
                                      'at': datetime.now(timezone.utc).isoformat(timespec='seconds')})
        if not deep and s.enable_active_enrichment and any(not (u.trusted and not u.rules) for u in url_results):
            from ..workers.queue import get_queue
            if get_queue().has_worker:  # serverless has no background workers: use ?deep=true there instead
                get_queue().submit('deepen', {'detection_id': det_id})
    return report


def get_graph_store_node_risk(det_id: str, url_results: list[URLResult], risk: float) -> None:
    from .graph_store import get_graph_store
    gs = get_graph_store()
    gs.upsert_node(f'email:{det_id}', 'email', {'risk': risk})
    if risk >= 60:  # the message's own untrusted domains inherit the verdict as graph evidence for future messages
        for u in url_results:
            if u.parsed.host and not u.trusted:
                gs.upsert_node(f'domain:{u.parsed.host}', 'domain', {'risk': max(risk, u.score)})


def _persist(det_id: str, pm: ParsedMessage, url_results: list[URLResult], report: dict, fusion, campaign_id, latency, source, demo, kind) -> None:
    import hashlib
    with session_scope() as s:
        existing = s.get(Detection, det_id)
        if existing:  # re-score after deep enrichment
            existing.risk_score, existing.decision = fusion.final, fusion.decision
            existing.scores, existing.reasons, existing.report = fusion.scores, report['reasons'], report
            existing.campaign_id = campaign_id or existing.campaign_id
            existing.conflicting_intelligence = fusion.conflicting_intelligence
            return
        email_id = None
        if kind == 'email' or pm.subject or pm.text:
            email_id = det_id
            s.add(Email(id=det_id, channel=pm.channel, message_id=pm.message_id[:300], sender=pm.sender[:320], sender_domain=pm.sender_domain[:255],
                        sender_name=pm.sender_name[:300], subject=pm.subject[:1000], body_excerpt=pm.text[:4000], auth=pm.auth,
                        attachments=[a.__dict__ for a in pm.attachments], source=source, demo=demo))
            s.flush()
        for u in url_results:
            h = hashlib.sha256(u.parsed.normalized.encode()).hexdigest()
            rec = s.query(URLRecord).filter_by(url_hash=h).one_or_none()
            if rec:
                rec.times_seen += 1
                rec.last_seen = datetime.now(timezone.utc)
                rec.risk = max(rec.risk, u.score)
            else:
                rec = URLRecord(url=u.parsed.normalized, url_hash=h, host=u.parsed.host or '', registrable=u.parsed.registrable or '', risk=u.score)
                s.add(rec)
                s.flush()
            if email_id:
                s.add(EmailURL(email_id=email_id, url_id=rec.id, sources=u.sources))
        s.add(Detection(id=det_id, email_id=email_id, kind=kind, target=report['title'][:500], risk_score=fusion.final, decision=fusion.decision,
                        scores=fusion.scores, reasons=report['reasons'], report=report, campaign_id=campaign_id,
                        conflicting_intelligence=fusion.conflicting_intelligence, latency_ms=latency, model_versions=_model_versions(), demo=demo))


async def deepen(detection_id: str) -> dict | None:
    """Background job: re-run a stored detection with full enrichment + external intel, then emit an update."""
    from .email_parser import parse_json_message
    with session_scope() as s:
        d = s.get(Detection, detection_id)
        if not d:
            return None
        rep = d.report or {}
        old = d.risk_score
        msg = rep.get('message', {})
    pm = parse_json_message(subject=msg.get('subject', ''), sender=msg.get('sender', ''), body=msg.get('text', ''), channel=msg.get('channel', 'email'),
                            reply_to=msg.get('reply_to', ''), sender_name=msg.get('sender_name', ''))
    pm.auth = msg.get('auth', {})
    if not pm.urls and rep.get('urls'):
        from .url_extractor import extract_urls
        pm.urls = extract_urls('\n'.join(u['url'] for u in rep['urls']))
    report = await analyze(pm, source='deep', deep=True, demo=bool(rep.get('demo')), persist=False, detection_id=detection_id, kind=rep.get('kind', 'email'))
    fusion_obj = type('F', (), {'final': report['risk_score'], 'decision': report['decision'], 'scores': report['scores'],
                                'conflicting_intelligence': report['conflicting_intelligence']})
    await asyncio.to_thread(_persist, detection_id, pm, [], report, fusion_obj, report.get('campaign', {}) and report['campaign'].get('id'), 0, 'deep', False, 'email')
    bus.publish('detection_updated', {'detection_id': detection_id, 'risk': report['risk_score'], 'previous_risk': old, 'decision': report['decision'],
                                      'title': report['title'], 'at': datetime.now(timezone.utc).isoformat(timespec='seconds')})
    if report['decision'] != (rep.get('decision')):
        await asyncio.to_thread(respond, detection_id, report['decision'], pm, 'deep')
    return report
