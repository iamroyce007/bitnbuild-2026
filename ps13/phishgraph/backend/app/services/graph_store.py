"""Temporal property graph with two interchangeable backends.

  Neo4jStore     production (NEO4J_URI set): MERGE nodes by id, typed relationships, properties on edges
  NetworkXStore  local / tests: in-memory MultiDiGraph persisted to data/graph.json

Every edge carries first_seen, last_seen, source and confidence. Node ids are '<type>:<key>'
(email, url, domain, ip, asn, cert, ns, brand, campaign, sender, attachment, feed, org).
Graph algorithms always run on a k-hop NetworkX subgraph pulled from whichever backend is active.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

import networkx as nx

from ..config import get_settings

log = logging.getLogger(__name__)
LABELS = {'email': 'Email', 'url': 'URL', 'domain': 'Domain', 'ip': 'IP', 'asn': 'ASN', 'cert': 'Certificate', 'ns': 'Nameserver', 'brand': 'Brand',
          'campaign': 'Campaign', 'sender': 'Sender', 'attachment': 'Attachment', 'feed': 'ThreatFeed', 'org': 'Organization'}


def iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


class NetworkXStore:
    backend = 'networkx'

    def __init__(self) -> None:
        self.g = nx.MultiDiGraph()
        self.path = get_settings().data_dir / 'graph.json'
        self.lock = threading.RLock()
        self._dirty = 0
        self._last_save = time.time()
        if self.path.exists():
            try:
                self.g = nx.node_link_graph(json.loads(self.path.read_text()), directed=True, multigraph=True, edges='links')
            except Exception as e:
                log.warning('could not load graph snapshot: %s', e)

    def upsert_node(self, nid: str, ntype: str, props: dict | None = None) -> None:
        with self.lock:
            now = iso()
            if nid in self.g:
                d = self.g.nodes[nid]
                d['last_seen'] = now
                for k, v in (props or {}).items():
                    if k == 'risk':
                        d['risk'] = max(float(d.get('risk') or 0), float(v or 0))
                    elif k == 'malicious':
                        d['malicious'] = bool(d.get('malicious')) or bool(v)
                    elif v is not None:
                        d[k] = v
            else:
                self.g.add_node(nid, type=ntype, first_seen=now, last_seen=now, **{k: v for k, v in (props or {}).items() if v is not None})
            self._touch()

    def upsert_edge(self, src: str, dst: str, rel: str, source: str = 'observed', confidence: float = 1.0, props: dict | None = None) -> None:
        with self.lock:
            now = iso()
            if self.g.has_edge(src, dst, key=rel):
                e = self.g.edges[src, dst, rel]
                e['last_seen'] = now
                e['count'] = e.get('count', 1) + 1
                e['confidence'] = max(e.get('confidence', 0), confidence)
            else:
                self.g.add_edge(src, dst, key=rel, rel=rel, first_seen=now, last_seen=now, source=source, confidence=confidence, count=1, **(props or {}))
            self._touch()

    def set_props(self, nid: str, props: dict) -> None:
        with self.lock:
            if nid in self.g:
                self.g.nodes[nid].update(props)
                self._touch()

    def node(self, nid: str) -> dict | None:
        with self.lock:
            return dict(self.g.nodes[nid], id=nid) if nid in self.g else None

    def degree(self, nid: str) -> int:
        with self.lock:
            return self.g.degree(nid) if nid in self.g else 0

    def subgraph(self, seeds: list[str], depth: int = 2, limit: int = 600) -> nx.MultiDiGraph:
        with self.lock:
            seen = {s for s in seeds if s in self.g}
            frontier = set(seen)
            for _ in range(depth):
                nxt = set()
                for n in frontier:
                    nb = list(self.g.successors(n)) + list(self.g.predecessors(n))
                    if len(nb) > 150:  # hub: include but do not expand through it
                        nb = nb[:25]
                    nxt.update(nb)
                nxt -= seen
                seen |= nxt
                frontier = {n for n in nxt if self.g.degree(n) <= 150}
                if len(seen) > limit:
                    break
            return self.g.subgraph(list(seen)[:limit]).copy()

    def nodes_by_type(self, ntype: str, limit: int = 500) -> list[dict]:
        with self.lock:
            out = [dict(d, id=n) for n, d in self.g.nodes(data=True) if d.get('type') == ntype]
        out.sort(key=lambda d: d.get('last_seen', ''), reverse=True)
        return out[:limit]

    def stats(self) -> dict:
        with self.lock:
            types: dict[str, int] = {}
            for _, d in self.g.nodes(data=True):
                types[d.get('type', '?')] = types.get(d.get('type', '?'), 0) + 1
            return {'backend': self.backend, 'nodes': self.g.number_of_nodes(), 'edges': self.g.number_of_edges(), 'by_type': types}

    def _touch(self) -> None:
        self._dirty += 1
        if self._dirty >= 200 or time.time() - self._last_save > 30:
            self.save()

    def save(self) -> None:
        with self.lock:
            if not self._dirty:
                return
            tmp = self.path.with_suffix('.tmp')
            tmp.write_text(json.dumps(nx.node_link_data(self.g, edges='links'), default=str))
            tmp.replace(self.path)
            self._dirty = 0
            self._last_save = time.time()

    def clear(self) -> None:
        with self.lock:
            self.g.clear()
            self._dirty = 1
            self.save()


class Neo4jStore(NetworkXStore):
    """Writes through to Neo4j; reads k-hop neighbourhoods back into NetworkX for analysis."""
    backend = 'neo4j'

    def __init__(self) -> None:
        from neo4j import GraphDatabase
        s = get_settings()
        self.driver = GraphDatabase.driver(s.neo4j_uri, auth=(s.neo4j_user, s.neo4j_password))
        self.driver.verify_connectivity()
        self.lock = threading.RLock()
        with self.driver.session() as ses:
            ses.run('CREATE CONSTRAINT node_id IF NOT EXISTS FOR (n:Node) REQUIRE n.id IS UNIQUE')

    def upsert_node(self, nid: str, ntype: str, props: dict | None = None) -> None:
        p = {k: v for k, v in (props or {}).items() if v is not None and not isinstance(v, (dict, list))}
        label = LABELS.get(ntype, 'Node')
        q = f'MERGE (n:Node {{id:$id}}) ON CREATE SET n.first_seen=$now, n.type=$t SET n:{label}, n.last_seen=$now, n += $p'
        risk = p.pop('risk', None)
        mal = p.pop('malicious', None)
        with self.driver.session() as ses:
            ses.run(q, id=nid, t=ntype, now=iso(), p=p)
            if risk is not None:
                ses.run('MATCH (n:Node {id:$id}) SET n.risk = CASE WHEN coalesce(n.risk,0) < $r THEN $r ELSE n.risk END', id=nid, r=float(risk))
            if mal:
                ses.run('MATCH (n:Node {id:$id}) SET n.malicious = true', id=nid)

    def upsert_edge(self, src: str, dst: str, rel: str, source: str = 'observed', confidence: float = 1.0, props: dict | None = None) -> None:
        with self.driver.session() as ses:
            ses.run(f'MATCH (a:Node {{id:$s}}), (b:Node {{id:$d}}) MERGE (a)-[r:{rel}]->(b) '
                    'ON CREATE SET r.first_seen=$now, r.source=$src, r.confidence=$c, r.count=1 '
                    'ON MATCH SET r.count = coalesce(r.count,1)+1, r.confidence = CASE WHEN r.confidence < $c THEN $c ELSE r.confidence END '
                    'SET r.last_seen=$now', s=src, d=dst, now=iso(), src=source, c=confidence)

    def set_props(self, nid: str, props: dict) -> None:
        p = {k: v for k, v in props.items() if not isinstance(v, (dict, list))}
        with self.driver.session() as ses:
            ses.run('MATCH (n:Node {id:$id}) SET n += $p', id=nid, p=p)

    def node(self, nid: str) -> dict | None:
        with self.driver.session() as ses:
            r = ses.run('MATCH (n:Node {id:$id}) RETURN n', id=nid).single()
            return dict(r['n']) if r else None

    def degree(self, nid: str) -> int:
        with self.driver.session() as ses:
            r = ses.run('MATCH (n:Node {id:$id})--() RETURN count(*) AS c', id=nid).single()
            return r['c'] if r else 0

    def subgraph(self, seeds: list[str], depth: int = 2, limit: int = 600) -> nx.MultiDiGraph:
        g = nx.MultiDiGraph()
        with self.driver.session() as ses:
            res = ses.run(f'MATCH (s:Node) WHERE s.id IN $ids MATCH p=(s)-[*0..{int(depth)}]-(m) '
                          'WHERE all(x IN nodes(p)[1..-1] WHERE COUNT {{ (x)--() }} <= 150) '
                          'WITH p LIMIT $lim UNWIND relationships(p) AS r RETURN DISTINCT startNode(r) AS a, type(r) AS t, properties(r) AS rp, endNode(r) AS b',
                          ids=seeds, lim=limit)
            for rec in res:
                a, b = dict(rec['a']), dict(rec['b'])
                g.add_node(a['id'], **a)
                g.add_node(b['id'], **b)
                g.add_edge(a['id'], b['id'], key=rec['t'], rel=rec['t'], **rec['rp'])
            for sid in seeds:
                if sid not in g:
                    n = self.node(sid)
                    if n:
                        g.add_node(sid, **n)
        return g

    def nodes_by_type(self, ntype: str, limit: int = 500) -> list[dict]:
        with self.driver.session() as ses:
            return [dict(r['n']) for r in ses.run('MATCH (n:Node {type:$t}) RETURN n ORDER BY n.last_seen DESC LIMIT $l', t=ntype, l=limit)]

    def stats(self) -> dict:
        with self.driver.session() as ses:
            n = ses.run('MATCH (n) RETURN count(n) AS c').single()['c']
            e = ses.run('MATCH ()-[r]->() RETURN count(r) AS c').single()['c']
            types = {r['t']: r['c'] for r in ses.run('MATCH (n:Node) RETURN n.type AS t, count(*) AS c')}
        return {'backend': self.backend, 'nodes': n, 'edges': e, 'by_type': types}

    def save(self) -> None:
        pass

    def clear(self) -> None:
        with self.driver.session() as ses:
            ses.run('MATCH (n) DETACH DELETE n')


_store: Any = None


def get_graph_store():
    global _store
    if _store is None:
        if get_settings().neo4j_uri:
            try:
                _store = Neo4jStore()
            except Exception as e:
                log.error('Neo4j unavailable (%s); falling back to NetworkX store', e)
                _store = NetworkXStore()
        else:
            _store = NetworkXStore()
    return _store
