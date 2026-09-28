"""Threat-graph ingestion and graph-derived risk.

GraphRisk (0-100) =  0.25 malicious_neighbors + 0.20 infrastructure_overlap + 0.15 suspicious_domain_cluster
                   + 0.15 ip_reputation      + 0.10 certificate_overlap    + 0.10 temporal_proximity
                   + 0.05 campaign_similarity
(each component normalised to 0-1).

Hub dampening keeps shared infrastructure from inventing links: an IP inside a CDN / cloud ASN, a
registrar's default nameserver, or any node with a large degree contributes little. Identical TLS
certificates and uncommon nameservers contribute a lot. Every contributing link is returned as an
explicit path, e.g. Email -> URL -> Domain -[RESOLVES_TO]-> IP <-[RESOLVES_TO]- known-bad Domain.
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone

import networkx as nx

from .graph_store import get_graph_store

# infrastructure shared by millions of unrelated sites: weak evidence when shared
SHARED_ASNS = {'AS13335', 'AS20940', 'AS16625', 'AS54113', 'AS16509', 'AS14618', 'AS15169', 'AS396982', 'AS8075', 'AS36459', 'AS14061',
               'AS24940', 'AS16276', 'AS63949', 'AS46606', 'AS26496', 'AS19551', 'AS209242', 'AS397273', 'AS8560', 'AS13238', 'AS32934', 'AS20473'}
SHARED_NS_SUFFIX = ('cloudflare.com', 'domaincontrol.com', 'registrar-servers.com', 'awsdns', 'googledomains.com', 'google.com', 'azure-dns', 'nsone.net',
                    'dnsmadeeasy.com', 'ultradns', 'akam.net', 'name.com', 'hostgator.com', 'bluehost.com', 'wixdns.net', 'squarespacedns.com',
                    'digitalocean.com', 'linode.com', 'hostinger', 'dns-parking.com', 'namecheaphosting.com', 'godaddy', 'ovh.net', 'hetzner', 'vercel-dns.com',
                    'netlify', 'dynect.net', 'cscdns.net', 'markmonitor.com', 'amazon.com', 'microsoft.com', 'zdns.google', 'afternic.com', 'sedoparking.com')
W = {'malicious_neighbors': 0.25, 'infrastructure_overlap': 0.20, 'suspicious_domain_cluster': 0.15, 'ip_reputation': 0.15,
     'certificate_overlap': 0.10, 'temporal_proximity': 0.10, 'campaign_similarity': 0.05}
INFRA_RELS = ('RESOLVES_TO', 'USES_NS', 'USES_CERT')


def url_node(u: str) -> str:
    return 'url:' + hashlib.sha256(u.encode()).hexdigest()[:20]


@dataclass
class GraphRisk:
    score: float
    components: dict[str, float]
    paths: list[dict] = field(default_factory=list)  # {kind, weight, nodes:[{id,type,label}], text}
    bad_neighbors: list[str] = field(default_factory=list)
    data_quality: str = 'limited'  # limited | partial | good
    available: bool = True


def _label(g, n: str) -> str:
    return g.nodes[n].get('label') or n.split(':', 1)[1]


def _is_bad(d: dict) -> bool:
    return bool(d.get('malicious')) or float(d.get('risk') or 0) >= 75


def _specificity(g, n: str) -> float:
    """How much sharing this infrastructure node means (1 = rare/unique, ~0 = shared by everyone)."""
    d = g.nodes[n]
    t = d.get('type')
    deg = max(1, g.degree(n))
    hub = 1 / math.log2(1 + deg) if deg > 4 else 1.0
    if t == 'ip':
        return (0.15 if d.get('asn') in SHARED_ASNS else 0.9) * hub
    if t == 'ns':
        return (0.05 if any(s in n for s in SHARED_NS_SUFFIX) else 0.7) * hub
    if t == 'cert':
        return 0.95 * hub
    if t == 'asn':
        return (0.02 if n.split(':', 1)[1] in SHARED_ASNS else 0.25) * hub
    return 0.3 * hub


def _nodes(g, ids) -> list[dict]:
    return [{'id': n, 'type': g.nodes[n].get('type'), 'label': _label(g, n)} for n in ids]


def ingest(detection_id: str, pm, url_results: list, enrichment: dict[str, dict], ti_results: list, risk: float | None = None, demo: bool = False) -> list[str]:
    """Write the message's entities and infrastructure into the graph. Returns seed node ids for scoring."""
    gs = get_graph_store()
    email_id = f'email:{detection_id}'
    gs.upsert_node(email_id, 'email', {'label': (pm.subject or pm.sender or 'message')[:80], 'channel': pm.channel, 'risk': risk, 'demo': demo})
    seeds: list[str] = []
    if pm.sender:
        sid = f'sender:{pm.sender}'
        gs.upsert_node(sid, 'sender', {'label': pm.sender})
        gs.upsert_edge(email_id, sid, 'SENT_BY')
        if pm.sender_domain:
            gs.upsert_node(f'domain:{pm.sender_domain}', 'domain', {'label': pm.sender_domain})
            gs.upsert_edge(sid, f'domain:{pm.sender_domain}', 'SENDER_DOMAIN')
    for a in pm.attachments:
        aid = f'attachment:{a.sha256[:32]}'
        gs.upsert_node(aid, 'attachment', {'label': a.filename, 'risky': a.risky})
        gs.upsert_edge(email_id, aid, 'HAS_ATTACHMENT')
    for ur in url_results:
        p = ur.parsed
        uid = url_node(p.normalized)
        gs.upsert_node(uid, 'url', {'label': p.normalized[:120], 'risk': ur.score})
        gs.upsert_edge(email_id, uid, 'CONTAINS')
        if not p.host:
            continue
        did = f'domain:{p.host}'
        gs.upsert_node(did, 'domain', {'label': p.host_unicode, 'registrable': p.registrable, 'risk': ur.score,
                                        'tranco_rank': ur.brand.tranco_rank if ur.brand else None})
        gs.upsert_edge(uid, did, 'HOSTED_ON')
        seeds += [uid, did]
        if p.registrable and p.registrable != p.host:
            rid = f'domain:{p.registrable}'
            gs.upsert_node(rid, 'domain', {'label': p.registrable})
            gs.upsert_edge(did, rid, 'SUBDOMAIN_OF')
        if ur.brand and ur.brand.findings:
            f = ur.brand.findings[0]
            bid = f'brand:{(f.brand or f.target_domain).lower()}'
            gs.upsert_node(bid, 'brand', {'label': f.brand or f.target_domain})
            gs.upsert_edge(did, bid, 'IMPERSONATES', source='brand_engine', confidence=f.confidence, props={'kind': f.kind})
        enr = enrichment.get(p.host) or {}
        asn = next((a for a in (enr.get('asn') or []) if a), None)
        for ip in (enr.get('dns') or {}).get('a', [])[:4]:
            gs.upsert_node(f'ip:{ip}', 'ip', {'label': ip, 'asn': asn['asn'] if asn else None, 'country': asn['country'] if asn else None})
            gs.upsert_edge(did, f'ip:{ip}', 'RESOLVES_TO', source='dns')
            if asn:
                gs.upsert_node(f'asn:{asn["asn"]}', 'asn', {'label': f'{asn["asn"]} {asn.get("name", "")}'.strip()})
                gs.upsert_edge(f'ip:{ip}', f'asn:{asn["asn"]}', 'BELONGS_TO', source='team-cymru')
        for ns in (enr.get('dns') or {}).get('ns', [])[:4]:
            gs.upsert_node(f'ns:{ns}', 'ns', {'label': ns})
            gs.upsert_edge(did, f'ns:{ns}', 'USES_NS', source='dns')
        tls = enr.get('tls')
        if tls:
            cid = f'cert:{tls["sha256"][:32]}'
            gs.upsert_node(cid, 'cert', {'label': (tls.get('issuer') or '')[:60], 'age_days': tls.get('age_days')})
            gs.upsert_edge(did, cid, 'USES_CERT', source='tls')
        rd = enr.get('rdap') or {}
        if rd.get('age_days') is not None:
            gs.set_props(did, {'age_days': rd['age_days'], 'registrar': rd.get('registrar')})
    for t in ti_results:
        if t.status != 'ok' or t.verdict not in ('malicious', 'suspicious'):
            continue
        fid = f'feed:{t.source}'
        gs.upsert_node(fid, 'feed', {'label': t.source})
        typ = {'url': 'url', 'domain': 'domain', 'ip': 'ip', 'hash': 'attachment'}[t.ioc_type]
        target = url_node(t.indicator) if typ == 'url' else f'{typ}:{t.indicator}'
        gs.upsert_node(target, typ, {'risk': t.risk, 'malicious': t.verdict == 'malicious', 'label': t.indicator[:120]})
        gs.upsert_edge(target, fid, 'LISTED_IN', source=t.source, confidence=t.confidence)
        for rel in t.relations[:20]:
            rtyp = {'ip': 'ip', 'domain': 'domain', 'nameserver': 'ns', 'asn': 'asn'}.get(rel['type'])
            if rtyp and rel.get('value'):
                rid = f'{rtyp}:{rel["value"]}'
                gs.upsert_node(rid, rtyp, {'label': rel['value']})
                gs.upsert_edge(target, rid, rel['rel'], source=t.source, confidence=0.7)
    return list(dict.fromkeys(seeds))


def mark(node_ids: list[str], malicious: bool, risk: float | None = None) -> None:
    gs = get_graph_store()
    for n in node_ids:
        if malicious:
            gs.upsert_node(n, n.split(':', 1)[0], {'malicious': True, 'risk': risk})
        else:
            gs.set_props(n, {'malicious': False, 'risk': 0.0})


def score(seeds: list[str], exclude: str | None = None, campaign_similarity: float = 0.0) -> GraphRisk:
    g = get_graph_store().subgraph(seeds, depth=3)
    if exclude and exclude in g:
        g.remove_node(exclude)
    domains = [s for s in seeds if s.startswith('domain:') and s in g]
    comps = dict.fromkeys(W, 0.0)
    paths: list[dict] = []
    has_infra = any(d.get('rel') in INFRA_RELS for _, _, d in g.edges(data=True))
    ug = nx.Graph(g)
    seedset = set(seeds)

    # 1. known-bad nodes near the message (graph distance), ignoring paths that only run through hubs
    bad = {n for n, d in g.nodes(data=True) if _is_bad(d) and n not in seedset}
    for s in seeds:
        if s in g and g.nodes[s].get('malicious'):
            comps['malicious_neighbors'] = 1.0
            paths.append({'kind': 'known_ioc', 'weight': 1.0, 'nodes': _nodes(g, [s]), 'text': f'{_label(g, s)} is itself a known-malicious indicator'})
    near = []
    for s in seeds:
        if s not in ug:
            continue
        lengths = nx.single_source_shortest_path_length(ug, s, cutoff=3)
        for b in bad:
            if lengths.get(b, 0) > 0:
                p = nx.shortest_path(ug, s, b)
                spec = min((_specificity(g, n) for n in p[1:-1] if g.nodes[n].get('type') in ('ip', 'ns', 'cert', 'asn')), default=1.0)
                if spec >= 0.3:  # paths through CDN / registrar-default infrastructure prove nothing
                    near.append((lengths[b], spec, p))
    near.sort(key=lambda x: (x[0], -x[1]))
    seen_bad: set[str] = set()
    val = 0.0
    for d, spec, p in near:
        if p[-1] in seen_bad:
            continue
        seen_bad.add(p[-1])
        val += spec / d
        if len(paths) < 6:
            paths.append({'kind': 'near_known_bad', 'weight': round(spec / d, 3), 'nodes': _nodes(g, p),
                          'text': ' → '.join(_label(g, n) for n in p) + f'  ({d} hop{"s" if d > 1 else ""} to a known-bad {g.nodes[p[-1]].get("type")})'})
    comps['malicious_neighbors'] = max(comps['malicious_neighbors'], min(1.0, val / 2))

    # 2/3/5. infrastructure overlap with suspicious domains, specificity-weighted
    overlap, cert_overlap = 0.0, 0.0
    related: dict[str, float] = {}
    shared: dict[tuple[str, str], list[tuple[str, float]]] = {}  # (my domain, other domain) -> [(infra node, contribution)]
    for dnode in domains:
        for _, infra, ed in g.out_edges(dnode, data=True):
            if ed.get('rel') not in INFRA_RELS:
                continue
            spec = _specificity(g, infra)
            if spec < 0.3:  # shared by huge numbers of unrelated sites: not a relationship
                continue
            for other, _, ed2 in g.in_edges(infra, data=True):
                if other == dnode or other in seedset or not other.startswith('domain:') or ed2.get('rel') != ed.get('rel'):
                    continue
                od = g.nodes[other]
                orisk = 1.0 if od.get('malicious') else float(od.get('risk') or 0) / 100
                related[other] = max(related.get(other, 0.0), orisk)
                if orisk < 0.5:
                    continue
                c = spec * orisk
                overlap += c
                if ed['rel'] == 'USES_CERT':
                    cert_overlap = max(cert_overlap, c)
                shared.setdefault((dnode, other), []).append((infra, c))
    NAMES = {'ip': 'IP', 'ns': 'nameserver', 'cert': 'TLS certificate'}
    for (dnode, other), items in shared.items():
        w = min(1.0, sum(c for _, c in items))
        if w < 0.08:
            continue
        what = ', '.join(f'{NAMES.get(g.nodes[i].get("type"), g.nodes[i].get("type"))} {_label(g, i)}' for i, _ in sorted(items, key=lambda x: -x[1]))
        bad_kind = 'known-bad' if g.nodes[other].get('malicious') else 'suspicious'
        paths.append({'kind': 'shared_infrastructure', 'weight': round(w, 3), 'nodes': _nodes(g, [dnode, *(i for i, _ in items), other]),
                      'text': f'{_label(g, dnode)} shares {what} with {bad_kind} domain {_label(g, other)}'})
    comps['infrastructure_overlap'] = min(1.0, overlap / 1.5)
    comps['certificate_overlap'] = min(1.0, cert_overlap)
    if related:
        comps['suspicious_domain_cluster'] = sum(1 for v in related.values() if v >= 0.5) / len(related)

    # 4. IP reputation on this message's own IPs
    for dnode in domains:
        for _, ip, ed in g.out_edges(dnode, data=True):
            if ed.get('rel') == 'RESOLVES_TO':
                ab = g.nodes[ip].get('abuse_confidence')
                if ab is not None:
                    comps['ip_reputation'] = max(comps['ip_reputation'], float(ab) / 100)
                if g.nodes[ip].get('malicious'):
                    comps['ip_reputation'] = max(comps['ip_reputation'], 0.9)

    # 6. temporal proximity: suspicious neighbours first seen within 7 days
    now = datetime.now(timezone.utc)
    recent = 0
    for other, r in related.items():
        fs = g.nodes[other].get('first_seen')
        if r >= 0.5 and fs:
            try:
                recent += (now - datetime.fromisoformat(str(fs))).days <= 7
            except ValueError:
                pass
    comps['temporal_proximity'] = min(1.0, recent / 3)
    comps['campaign_similarity'] = max(0.0, min(1.0, campaign_similarity))

    total = sum(W[k] * v for k, v in comps.items())
    quality = 'good' if has_infra and g.number_of_nodes() > 8 else 'partial' if has_infra or bad else 'limited'
    covered = {o for _, o in shared}
    paths = [p for p in paths if not (p['kind'] == 'near_known_bad' and p['nodes'][-1]['id'] in covered)]  # already explained above
    paths.sort(key=lambda p: -p['weight'])
    return GraphRisk(score=round(100 * total, 1), components={k: round(v, 3) for k, v in comps.items()}, paths=paths[:8],
                     bad_neighbors=sorted(bad)[:20], data_quality=quality)
