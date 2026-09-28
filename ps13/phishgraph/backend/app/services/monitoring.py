"""Model health & drift: compares recent production traffic with the training reference.

  score drift       PSI of the fused risk-score distribution (last 24 h vs everything before)
  phishing ratio    share of FLAG+ decisions vs training prevalence
  false positives   analyst-marked false positives / reviewed detections
  new TLDs          TLDs seen recently that never appeared before
  new impersonations brands impersonated recently that were not seen before
PSI > 0.25 is conventionally 'significant drift' and is surfaced as a retraining recommendation.
"""
from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ..database import session_scope
from ..ml.model_registry import active
from ..models.database_models import Detection, Feedback


def _psi(a: list[float], b: list[float], bins: int = 10) -> float | None:
    if len(a) < 20 or len(b) < 20:
        return None
    def hist(x):
        h = [0] * bins
        for v in x:
            h[min(bins - 1, int(v / (100 / bins)))] += 1
        n = len(x)
        return [max(c / n, 1e-4) for c in h]
    ha, hb = hist(a), hist(b)
    return round(sum((q - p) * math.log(q / p) for p, q in zip(ha, hb)), 4)


def drift_report() -> dict:
    now = datetime.now(timezone.utc)
    cut = now - timedelta(hours=24)
    with session_scope() as s:
        rows = s.execute(select(Detection.created_at, Detection.risk_score, Detection.decision, Detection.report).order_by(Detection.created_at.desc()).limit(5000)).all()
        fb = s.execute(select(Feedback.label)).scalars().all()
    def aware(t):
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    recent = [r for r in rows if aware(r[0]) >= cut]
    older = [r for r in rows if aware(r[0]) < cut]
    tld_old = Counter(u['host'].rsplit('.', 1)[-1] for r in older for u in (r[3] or {}).get('urls', []) if u.get('host'))
    tld_new = Counter(u['host'].rsplit('.', 1)[-1] for r in recent for u in (r[3] or {}).get('urls', []) if u.get('host'))
    br = lambda rs: Counter(f['brand'] for r in rs for u in (r[3] or {}).get('urls', []) for f in ((u.get('brand') or {}).get('findings') or []) if f.get('brand'))  # noqa: E731
    reviewed = len(fb)
    fp = sum(1 for x in fb if x == 'false_positive')
    em, um = active('email'), active('url')
    psi = _psi([r[1] for r in older], [r[1] for r in recent])
    return {
        'models': {'email': {'version': em['version'] if em else None, 'trained_at': em['trained_at'] if em else None,
                             'f1_random': em['report']['splits']['random_stratified']['blend']['f1'] if em else None,
                             'pr_auc_random': em['report']['splits']['random_stratified']['blend']['pr_auc'] if em else None,
                             'training_samples': em['report']['data']['n'] if em else None},
                   'url': {'version': um['version'] if um else None, 'trained_at': um['trained_at'] if um else None,
                           'f1_domain_grouped': um['report']['splits']['domain_grouped']['blend_mean']['f1'] if um else None,
                           'pr_auc_domain_grouped': um['report']['splits']['domain_grouped']['blend_mean']['pr_auc'] if um else None,
                           'training_samples': um['report']['data']['n'] if um else None}},
        'score_psi_24h': psi, 'drift_level': None if psi is None else 'significant' if psi > 0.25 else 'moderate' if psi > 0.1 else 'stable',
        'recent_detections': len(recent), 'phishing_ratio_24h': round(sum(1 for r in recent if r[2] != 'ALLOW') / len(recent), 3) if recent else None,
        'false_positive_rate_reviewed': round(fp / reviewed, 3) if reviewed else None, 'reviewed': reviewed,
        'confidence_histogram_24h': [sum(1 for r in recent if i * 10 <= r[1] < (i + 1) * 10 or (i == 9 and r[1] == 100)) for i in range(10)],
        'new_tlds_24h': sorted(set(tld_new) - set(tld_old))[:20], 'new_impersonated_brands_24h': sorted(set(br(recent)) - set(br(older)))[:20],
        'recommendation': 'retrain: significant score drift' if psi and psi > 0.25 else None,
    }
