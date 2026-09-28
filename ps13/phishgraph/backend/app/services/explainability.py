"""Assemble the explainable detection report. Every reason is copied from an engine's evidence; nothing is paraphrased
from a model. Reasons carry the engine that produced them so analysts can audit each one."""
from __future__ import annotations

from datetime import datetime, timezone

LABEL = {'nlp': 'Language', 'url': 'Link', 'brand': 'Brand', 'metadata': 'Sender', 'threat_intelligence': 'Threat intel', 'graph': 'Graph', 'evasion': 'Evasion'}


def _title(pm, nlp, url_results, meta) -> str:
    brand = next((u.brand.findings[0].brand for u in url_results if u.brand and u.brand.findings and u.brand.findings[0].brand), None) \
        or (meta.claimed_brands[0] if meta.claimed_brands else None)
    top_intent = nlp.intents[0].label if nlp and nlp.intents else None
    if pm.subject:
        return pm.subject[:140]
    if brand and top_intent:
        return f'{brand}: {top_intent.lower()}'
    if url_results:
        return url_results[0].parsed.host_unicode or url_results[0].parsed.normalized[:120]
    return (pm.text[:120] or 'message').strip()


def _timeline(enrichment: dict, ti, url_results, gr, now_iso: str) -> list[dict]:
    ev = []
    for host, e in enrichment.items():
        rd = e.get('rdap') or {}
        if rd.get('created'):
            ev.append({'at': rd['created'], 'event': f'{e.get("registrable", host)} registered' + (f' via {rd["registrar"]}' if rd.get('registrar') else ''), 'source': 'rdap'})
        tls = e.get('tls') or {}
        if tls.get('not_before'):
            ev.append({'at': tls['not_before'], 'event': f'TLS certificate issued for {host}', 'source': 'tls'})
    for r in ti.results:
        if r.status == 'ok' and r.verdict in ('malicious', 'suspicious'):
            for h in (r.details or {}).get('hits', [])[:1]:
                if h.get('first_seen'):
                    ev.append({'at': h['first_seen'], 'event': f'{r.indicator[:60]} listed by {h["source"]}', 'source': r.source})
            for rel in r.relations[:3]:
                if rel.get('first_seen'):
                    ev.append({'at': rel['first_seen'], 'event': f'{r.source} observed {rel["type"]} {rel["value"]}', 'source': r.source})
    ev.append({'at': now_iso, 'event': 'PhishGraph analysed the message', 'source': 'phishgraph'})
    ev.sort(key=lambda x: str(x['at']))
    return ev[-14:]


def build_report(det_id, pm, nlp, url_results, meta, ti, gr, fusion, enrichment, extra_rules, best_camp, camp_sim, campaign_id, *,
                 deep: bool, latency_ms: int, demo: bool) -> dict:
    now_iso = datetime.now(timezone.utc).isoformat(timespec='seconds')
    reasons: list[dict] = []

    def add(cat: str, text: str, weight: float, source: str) -> None:
        if text and weight > 0:
            reasons.append({'category': LABEL.get(cat, cat), 'text': text, 'weight': round(float(weight), 3), 'source': source})

    if nlp:
        for i in nlp.intents:
            ev = f' ("{i.evidence[0][:80]}")' if i.evidence else ''
            add('nlp', f'{i.label}{ev}' + (f' [semantic match {i.similarity}]' if i.source == 'semantic' else ''), i.weight, f'nlp:{i.source}')
        if nlp.p_stage1 is not None:
            add('nlp', f'Text classifier: {round(100 * (nlp.p_stage1 + (nlp.p_stage2 if nlp.p_stage2 is not None else nlp.p_stage1)) / 2)}% phishing-like language',
                0.5 * ((nlp.p_stage1 + (nlp.p_stage2 or nlp.p_stage1)) / 2) ** 2, 'nlp:model')
    for u in url_results:
        for r in u.rules:
            cat = 'brand' if r['id'].startswith('brand_') else 'url'
            add(cat, r['label'], r['weight'], f'url_engine:{r["id"]}')
        if u.ml_probability is not None and u.ml_probability >= 0.7 and not u.trusted:
            add('url', f'URL model: {round(100 * u.ml_probability)}% structural similarity to phishing URLs ({u.parsed.host})', 0.3 * u.ml_probability, 'url_engine:model')
    for r in extra_rules:
        add('url', r['label'], r['weight'], f'enrichment:{r["id"]}')
    for sgl in meta.signals:
        add('evasion' if sgl['id'].startswith('evasion_') else 'metadata', sgl['label'], sgl['weight'], f'metadata:{sgl["id"]}')
    for r in ti.hits:
        add('threat_intelligence', f'{r.source}: {r.summary}', (r.risk / 100) * r.confidence, f'ti:{r.source}')
    for p in gr.paths:
        add('graph', p['text'], p['weight'], f'graph:{p["kind"]}')
    if best_camp and camp_sim >= 0.45:
        add('graph', f'{round(100 * camp_sim)}% similar to {best_camp["id"]} ({best_camp["name"]})', 0.3 * camp_sim, 'campaign_engine')
    # de-duplicate identical texts, keep strongest
    seen: dict[str, dict] = {}
    for r in reasons:
        if r['text'] not in seen or seen[r['text']]['weight'] < r['weight']:
            seen[r['text']] = r
    reasons = sorted(seen.values(), key=lambda r: -r['weight'])[:24]

    ti_sources = []
    by_src: dict[str, list] = {}
    for r in ti.results:
        by_src.setdefault(r.source, []).append(r)
    for src, rs in by_src.items():
        ok = [r for r in rs if r.status == 'ok']
        status = 'ok' if ok else rs[0].status
        worst = max(ok, key=lambda r: r.risk * r.confidence, default=None)
        ti_sources.append({'source': src, 'status': status, 'display': 'SOURCE UNAVAILABLE' if status in ('unavailable', 'error', 'circuit_open') else
                           'NOT CONFIGURED' if status == 'not_configured' else 'DISABLED' if status == 'disabled' else status.upper(),
                           'verdict': worst.verdict if worst else None, 'summary': worst.summary if worst else rs[0].summary,
                           'lookups': len(rs), 'cached': sum(r.cached for r in rs)})

    highlights = []
    if nlp:
        for i in nlp.intents:
            for a, b in i.spans[:4]:
                highlights.append({'start': a, 'end': b, 'intent': i.id})

    return {
        'detection_id': det_id,
        'kind': 'email',
        'title': _title(pm, nlp, url_results, meta),
        'risk_score': fusion.final,
        'decision': fusion.decision,
        'scores': fusion.scores,
        'weights_used': fusion.weights_used,
        'unavailable_sources': fusion.unavailable,
        'overrides': fusion.overrides,
        'conflicting_intelligence': fusion.conflicting_intelligence,
        'conflict_detail': fusion.conflict_detail,
        'reasons': reasons,
        'message': {'channel': pm.channel, 'sender': pm.sender, 'sender_name': pm.sender_name, 'subject': pm.subject, 'text': pm.text[:20000],
                    'reply_to': pm.reply_to, 'auth': pm.auth, 'attachments': [a.__dict__ for a in pm.attachments], 'indicators': pm.indicators,
                    'tricks': pm.tricks, 'highlights': highlights},
        'nlp': None if not nlp else {'score': nlp.score, 'p_stage1': nlp.p_stage1, 'p_stage2': nlp.p_stage2, 'intent_score': nlp.intent_score,
                                     'intents': [{'id': i.id, 'label': i.label, 'weight': i.weight, 'evidence': i.evidence, 'source': i.source, 'similarity': i.similarity} for i in nlp.intents],
                                     'top_terms': nlp.top_terms, 'campaign_similarity': nlp.campaign_similarity, 'semantic_available': nlp.p_stage2 is not None},
        'urls': [{'url': u.parsed.normalized, 'display': u.parsed.host_unicode, 'host': u.parsed.host, 'registrable': u.parsed.registrable, 'score': u.score,
                  'ml_probability': u.ml_probability, 'trusted': u.trusted, 'rules': u.rules, 'top_ngrams': u.top_ngrams, 'sources': u.sources,
                  'unwrapped': u.parsed.unwrapped, 'deceptive_text': u.deceptive_text,
                  'brand': None if not u.brand else {'official': u.brand.official_brand, 'tranco_rank': u.brand.tranco_rank, 'established': u.brand.established,
                                                     'findings': [f.__dict__ for f in u.brand.findings], 'scripts': u.brand.scripts},
                  'enrichment': enrichment.get(u.parsed.host)} for u in url_results],
        'metadata': {'score': meta.score, 'signals': meta.signals, 'claimed_brands': meta.claimed_brands, 'sender': meta.sender_verdict},
        'threat_intel': {'score': ti.score if ti.available else None, 'sources': ti_sources, 'external_enabled': any(s['status'] == 'ok' and s['source'] != 'local_intel' for s in ti_sources)},
        'graph': {'score': gr.score, 'components': gr.components, 'paths': gr.paths, 'data_quality': gr.data_quality},
        'campaign': {'id': campaign_id, 'best_match': best_camp, 'similarity': camp_sim} if (campaign_id or best_camp) else None,
        'timeline': _timeline(enrichment, ti, url_results, gr, now_iso),
        'deep_analysis': deep,
        'latency_ms': latency_ms,
        'demo': demo,
        'analyzed_at': now_iso,
    }
