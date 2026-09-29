"""Analyst feedback loop.

confirmed_phishing -> indicators added to the local threat feed (source=analyst), graph nodes marked malicious,
                      message queued as a positive training sample
false_positive     -> graph nodes cleared, message queued as a HARD NEGATIVE (the most valuable retraining data)
unsure             -> recorded only
Retraining is approval-based: samples accumulate in data/processed/*.jsonl and a human runs scripts/train_all.py.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from ..config import get_settings
from ..database import session_scope
from ..models.database_models import AuditLog, Detection, Feedback
from . import graph_engine
from .graph_engine import url_node
from .intel_store import get_intel_store

LABELS = ('confirmed_phishing', 'false_positive', 'unsure')


def apply(detection_id: str, label: str, analyst: str = 'analyst', note: str = '') -> dict:
    if label not in LABELS:
        raise ValueError(f'label must be one of {LABELS}')
    with session_scope() as s:
        d = s.get(Detection, detection_id)
        if not d:
            raise KeyError(detection_id)
        rep = d.report or {}
        is_demo = bool(getattr(d, 'demo', False) or rep.get('demo'))
        d.status = {'confirmed_phishing': 'confirmed', 'false_positive': 'false_positive', 'unsure': 'unsure'}[label]
        s.add(Feedback(detection_id=detection_id, label=label, analyst=analyst, note=note[:2000]))
        s.add(AuditLog(actor=analyst, action=f'feedback.{label}', target=detection_id, detail={'note': note[:200]}))
    urls = [u for u in rep.get('urls', [])]
    untrusted = [u for u in urls if not u.get('trusted')]
    nodes = [url_node(u['url']) for u in untrusted] + [f'domain:{u["host"]}' for u in untrusted if u.get('host')]
    out: dict = {'detection_id': detection_id, 'label': label, 'iocs_added': 0}
    if label == 'confirmed_phishing':
        items = [('url', u['url']) for u in untrusted] + [('domain', u['host']) for u in untrusted if u.get('host') and u['host'] != u.get('registrable')]
        out['iocs_added'] = get_intel_store().add(items, source='analyst', tags=['confirmed'])
        graph_engine.mark(nodes, True, 95.0)
        graph_engine.mark([f'email:{detection_id}'], True, 95.0)
    elif label == 'false_positive':
        graph_engine.mark(nodes, False)
    msg = rep.get('message', {})
    if label != 'unsure' and msg.get('text'):
        path = get_settings().data_dir / 'processed' / ('hard_negatives.jsonl' if label == 'false_positive' else 'confirmed_phishing.jsonl')
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'a', encoding='utf-8') as f:
            f.write(json.dumps({'detection_id': detection_id, 'label': 1 if label == 'confirmed_phishing' else 0, 'subject': msg.get('subject'),
                                'text': msg.get('text', '')[:8000], 'urls': [u['url'] for u in urls], 'channel': msg.get('channel'),
                                'demo': is_demo, 'at': datetime.now(timezone.utc).isoformat()}) + '\n')
        out['queued_for_training'] = path.name
    from .events import bus
    bus.publish('feedback', {'detection_id': detection_id, 'label': label, 'iocs_added': out['iocs_added']})
    return out


def training_queue() -> dict:
    d = get_settings().data_dir / 'processed'
    count = lambda n: sum(1 for _ in open(d / n)) if (d / n).exists() else 0  # noqa: E731
    return {'hard_negatives': count('hard_negatives.jsonl'), 'confirmed_phishing': count('confirmed_phishing.jsonl')}
