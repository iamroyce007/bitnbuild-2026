"""Score the *deployed* URL model on today's live phishing (OpenPhish) versus real sites, excluding anything that was in
the training data. Run it any day to see how the model does on phishing it has never seen; the result is written into
models/url/report.json (key `fresh_feed`) and data/processed/fresh_feed_eval.json.

    python scripts/eval_fresh_feed.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))

import joblib  # noqa: E402
import numpy as np  # noqa: E402

from app.ml.train_url import feats, fresh_feed_eval, load  # noqa: E402


def main() -> None:
    m = joblib.load(ROOT / 'models' / 'url' / 'url_model.joblib')
    from sklearn.feature_extraction.text import HashingVectorizer
    from app.services.url_features import char_ngrams
    hv = HashingVectorizer(analyzer=char_ngrams, n_features=m['n_features'], alternate_sign=False, norm='l2')

    def predict(us: list[str]) -> np.ndarray:  # same path as url_engine: blend -> isotonic
        return m['iso'].predict((m['lr'].predict_proba(hv.transform(us))[:, 1] + m['hgb'].predict_proba(feats(us))[:, 1]) / 2)

    seen = set(load()['key'])
    res = fresh_feed_eval(predict, seen)
    print(json.dumps({k: v for k, v in res.items() if k != 'confusion'}, indent=1))
    (ROOT / 'data' / 'processed' / 'fresh_feed_eval.json').write_text(json.dumps(res, indent=1))
    rp = ROOT / 'models' / 'url' / 'report.json'
    rep = json.loads(rp.read_text())
    rep['fresh_feed'] = res
    rp.write_text(json.dumps(rep, indent=1))
    if res.get('status') == 'ok':
        from app.services import validation_log
        validation_log.append('fresh_feed', {k: res[k] for k in ('n_phishing', 'n_benign', 'recall_at_0.5', 'fp_rate_at_0.5', 'f1', 'pr_auc')},
                              {k: v for k, v in res.items() if k not in ('status',)}, target='models/url (deployed)')


if __name__ == '__main__':
    main()
