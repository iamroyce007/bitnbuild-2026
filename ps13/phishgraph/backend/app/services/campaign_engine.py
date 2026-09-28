"""Campaign clustering: semantic embedding similarity + shared infrastructure + brand targets + time.

similarity(message, campaign) = 0.50 cosine(embedding, campaign centroid)
                              + 0.30 infrastructure overlap (shared non-hub domains / IPs / certs / NS in the graph)
                              + 0.10 same impersonated brand
                              + 0.10 temporal proximity (seen within 14 days)
A suspicious message joins the best campaign above 0.55; a high-risk message with no match founds a new one.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone

import numpy as np
from sqlalchemy import func, select

from ..database import session_scope
from ..models.database_models import Campaign
from .graph_engine import _specificity
from .graph_store import get_graph_store

JOIN_THRESHOLD = 0.55
_lock = threading.Lock()
_INFRA_CACHE: dict[str, tuple[float, set[str]]] = {}  # campaign id -> (computed at, infrastructure node ids)
_INFRA_TTL = 120.0


def _infra(seeds: list[str]) -> set[str]:
    g = get_graph_store().subgraph(seeds, depth=2, limit=300)
    out = set()
    for n, d in g.nodes(data=True):
        if d.get('type') in ('ip', 'cert', 'ns', 'domain') and n not in seeds:
            if d.get('type') == 'domain' or _specificity(g, n) >= 0.3:
                out.add(n)
    return out | {s for s in seeds if s.startswith('domain:')}


def _campaign_infra(cid: str) -> set[str]:
    """Infrastructure reachable from a campaign (campaign -> email -> url -> domain -> ip/ns/cert = 5 hops).
    Cached per campaign and invalidated when the campaign gains a message, so matching stays O(campaigns)."""
    import time
    hit = _INFRA_CACHE.get(cid)
    if hit and time.time() - hit[0] < _INFRA_TTL:
        return hit[1]
    g = get_graph_store().subgraph([f'campaign:{cid}'], depth=5, limit=1500)
    out = {n for n, d in g.nodes(data=True) if d.get('type') in ('ip', 'cert', 'ns', 'domain') and (d.get('type') == 'domain' or _specificity(g, n) >= 0.3)}
    _INFRA_CACHE[cid] = (time.time(), out)
    return out


def match(embedding: np.ndarray | None, seeds: list[str], brands: list[str]) -> tuple[dict | None, float]:
    """Best matching campaign and its similarity (0-1); read-only."""
    with session_scope() as s:
        camps = s.execute(select(Campaign).order_by(Campaign.last_seen.desc()).limit(200)).scalars().all()
    if not camps:
        return None, 0.0
    mine = _infra(seeds)
    now = datetime.now(timezone.utc)
    # semantic similarity for every campaign in one matrix product
    sem_all = np.zeros(len(camps), dtype=np.float32)
    if embedding is not None:
        rows = [(i, c.centroid) for i, c in enumerate(camps) if c.centroid]
        if rows:
            M = np.asarray([r[1] for r in rows], dtype=np.float32)
            M /= np.linalg.norm(M, axis=1, keepdims=True) + 1e-9
            sem_all[[r[0] for r in rows]] = np.clip(M @ embedding, 0, None)
    best, best_sim = None, 0.0
    for i, c in enumerate(camps):
        sem = float(sem_all[i])
        infra = 0.0
        if mine and (sem >= 0.2 or len(camps) <= 60):  # only walk infrastructure for plausible candidates
            ci = _campaign_infra(c.id)
            if ci:
                infra = min(1.0, len(mine & ci) / 2)
        brand = 1.0 if brands and set(brands) & set(c.brands or []) else 0.0
        ls = c.last_seen if c.last_seen.tzinfo else c.last_seen.replace(tzinfo=timezone.utc)
        temporal = 1.0 if (now - ls).days <= 14 else 0.0
        sim = 0.5 * sem + 0.3 * infra + 0.1 * brand + 0.1 * temporal
        if sim > best_sim:
            best_sim = sim
            best = {'id': c.id, 'name': c.name, 'semantic': round(sem, 3), 'infrastructure': round(infra, 3), 'brand': brand, 'temporal': temporal}
    return best, round(best_sim, 3)


def assign(detection_id: str, embedding: np.ndarray | None, seeds: list[str], brands: list[str], intents: list[str], risk: float,
           best: dict | None, sim: float, demo: bool = False) -> str | None:
    """Join the matched campaign or create a new one. Returns the campaign id (or None)."""
    gs = get_graph_store()
    now = datetime.now(timezone.utc)
    with _lock, session_scope() as s:
        c = s.get(Campaign, best['id']) if best and sim >= JOIN_THRESHOLD else None
        if c is None:
            if risk < 60:
                return None
            year = now.year
            n = (s.execute(select(func.count()).select_from(Campaign)).scalar() or 0) + 1
            cid = f'CAMPAIGN-{year}-{n:04d}'
            while s.get(Campaign, cid):
                n += 1
                cid = f'CAMPAIGN-{year}-{n:04d}'
            target = brands[0] if brands else 'Unbranded'
            what = intents[0].replace('_', ' ') if intents else 'phishing'
            c = Campaign(id=cid, name=f'{target} {what}', risk=risk, brands=brands[:5], stats={'emails': 0}, first_seen=now, last_seen=now, demo=demo,
                         centroid=embedding.tolist() if embedding is not None else None)
            s.add(c)
            s.flush()
        else:
            if embedding is not None:
                k = max(1, int((c.stats or {}).get('emails', 1)))
                cen = np.asarray(c.centroid, dtype=np.float32) if c.centroid else embedding
                c.centroid = ((cen * k + embedding) / (k + 1)).tolist()
            c.brands = sorted(set(c.brands or []) | set(brands))[:8]
            c.risk = max(c.risk, risk)
            c.last_seen = now
        stats = dict(c.stats or {})
        stats['emails'] = int(stats.get('emails', 0)) + 1
        c.stats = stats
        cid = c.id
    _INFRA_CACHE.pop(cid, None)  # campaign changed: recompute its infrastructure next time
    gs.upsert_node(f'campaign:{cid}', 'campaign', {'label': cid, 'risk': risk})
    gs.upsert_edge(f'email:{detection_id}', f'campaign:{cid}', 'PART_OF', source='campaign_engine', confidence=max(sim, 0.6))
    refresh_stats(cid)
    return cid


def refresh_stats(cid: str) -> dict:
    g = get_graph_store().subgraph([f'campaign:{cid}'], depth=5, limit=2000)
    types: dict[str, set] = {}
    for n, d in g.nodes(data=True):
        types.setdefault(d.get('type'), set()).add(n)
    stats = {'emails': len([e for e in types.get('email', set()) if g.has_edge(e, f'campaign:{cid}')]), 'domains': len(types.get('domain', ())),
             'ips': len(types.get('ip', ())), 'asns': len(types.get('asn', ())), 'certificates': len(types.get('cert', ())),
             'nameservers': len(types.get('ns', ())), 'urls': len(types.get('url', ()))}
    with session_scope() as s:
        c = s.get(Campaign, cid)
        if c:
            c.stats = stats
    return stats
