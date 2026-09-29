"""Train and evaluate URL models with leakage-aware splits.

Sources (labels normalised to 1 = phishing):
  A  ealvaradob/phishing-dataset urls.json   (Apache-2.0)
  B  PhiUSIIL Phishing URL Dataset (UCI #967, CC BY 4.0) - label 0 = phishing there

Models: hashed char n-gram Logistic Regression, Random Forest and HistGradientBoosting on 37 lexical
features, plus a stacked blend. Splits reported: random stratified, domain-grouped (no registrable
domain in both train and test), and cross-source (train on one dataset, test on the other).
Deployed model = blend trained on the domain-grouped split, isotonic-calibrated on a held-out fold.

Run:  python -m app.ml.train_url
"""
from __future__ import annotations

import json
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from ..config import get_settings
from ..services.url_features import FEATURE_NAMES, char_ngrams, feature_vector
from ..utils.url_utils import parse_url
from .model_registry import register

S = get_settings()
RAW = S.data_dir / 'raw'
N_FEATURES = 2 ** 20
RNG = np.random.default_rng(7)


def load() -> pd.DataFrame:
    a = pd.read_json(RAW / 'urls.json')
    a = a.rename(columns={'text': 'url'})
    a['source'] = 'ealvaradob'
    b = pd.read_csv(RAW / 'PhiUSIIL_Phishing_URL_Dataset.csv', usecols=['URL', 'label'])
    b = b.rename(columns={'URL': 'url'})
    b['label'] = 1 - b['label']  # PhiUSIIL: 1 = legitimate
    b['source'] = 'phiusiil'
    df = pd.concat([a, b], ignore_index=True)
    df['url'] = df['url'].astype(str).str.strip()
    df['key'] = df['url'].str.lower().str.replace(r'^[a-z]+://', '', regex=True).str.replace(r'^www\.', '', regex=True).str.rstrip('/')
    before = len(df)
    df = df.drop_duplicates('key')
    conflict = df.groupby('key')['label'].nunique()
    df = df[~df['key'].isin(conflict[conflict > 1].index)]
    print(f'loaded {before} rows -> {len(df)} unique URLs; by source/label:\n{df.groupby(["source", "label"]).size()}')
    return df


def registrable_of(u: str) -> str:
    p = parse_url(u)
    return p.registrable if p and p.registrable else u.split('/')[0]


def metrics(y, p, thr=0.5) -> dict:
    yhat = (p >= thr).astype(int)
    pr, rc, f1, _ = precision_recall_fscore_support(y, yhat, average='binary', zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, yhat, labels=[0, 1]).ravel()
    return {'precision': round(pr, 4), 'recall': round(rc, 4), 'f1': round(f1, 4), 'roc_auc': round(roc_auc_score(y, p), 4),
            'pr_auc': round(average_precision_score(y, p), 4), 'confusion': {'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)}, 'n': int(len(y))}


def fit_char_lr(urls, y):
    hv = HashingVectorizer(analyzer=char_ngrams, n_features=N_FEATURES, alternate_sign=False, norm='l2')
    X = hv.transform(urls)
    m = LogisticRegression(C=4.0, max_iter=300, solver='liblinear', class_weight='balanced')
    m.fit(X, y)
    return hv, m


def feats(urls) -> np.ndarray:
    return np.array([feature_vector(u) for u in urls], dtype=np.float32)


def fresh_feed_eval(predict, seen_keys: set[str]) -> dict:
    """Today's live phishing (OpenPhish public feed) against real sites (Tranco ranks 20,001-23,000), none of them in the
    training data. This is the closest thing to "how does it do on phishing it has never seen, right now".
    Caveat, recorded in the result: the benign side is homepages only, because no public list of deep links on
    ordinary sites exists, so its false-positive rate is optimistic."""
    import httpx
    key = lambda u: u.lower().split('://', 1)[-1].removeprefix('www.').rstrip('/')
    try:
        feed = httpx.get('https://openphish.com/feed.txt', timeout=20, headers={'User-Agent': 'PhishGraph-training/1.0'}).text.split()
    except Exception as e:  # offline: report it, do not invent a number
        return {'status': 'unavailable', 'error': str(e)[:200]}
    phish = sorted({u.strip() for u in feed if u.startswith('http') and key(u) not in seen_keys})
    tranco = [line.split(',', 1)[1].strip() for line in (RAW / 'top-1m.csv').read_text().splitlines()[20_000:23_000] if ',' in line]
    benign = [f'https://{d}/' for d in tranco if key(d) not in seen_keys]
    if len(phish) < 20:
        return {'status': 'too_few', 'n_phishing': len(phish)}
    pp, pb = predict(phish), predict(benign)
    yt = np.r_[np.ones(len(pp)), np.zeros(len(pb))]
    m = metrics(yt, np.r_[pp, pb])
    return {'status': 'ok', 'at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'phishing_source': 'openphish.com/feed.txt (live)',
            'benign_source': 'Tranco ranks 20,001-23,000 homepages', 'n_phishing': len(phish), 'n_benign': len(benign),
            'recall_at_0.5': round(float((pp >= 0.5).mean()), 4), 'fp_rate_at_0.5': round(float((pb >= 0.5).mean()), 4), **m,
            'caveat': 'benign side is homepages only, so the false-positive rate is optimistic; the recall is the meaningful number'}


def main() -> None:
    t0 = time.time()
    df = load()
    seen_keys = set(df['key'])
    df = df.sample(n=min(len(df), 420_000), random_state=7).reset_index(drop=True)
    print('computing registrable domains + lexical features...')
    df['reg'] = [registrable_of(u) for u in df['url']]
    F = feats(df['url'])
    y = df['label'].to_numpy()
    urls = df['url'].tolist()
    report: dict = {'data': {'n': int(len(df)), 'by_source': df.groupby('source').size().to_dict(),
                             'phishing_ratio': round(float(y.mean()), 4)}, 'splits': {}}
    print(f'features done in {time.time() - t0:.0f}s')

    def evaluate(name, tr, te, blend=True):
        res = {}
        hv, lr = fit_char_lr([urls[i] for i in tr], y[tr])
        p_lr = lr.predict_proba(hv.transform([urls[i] for i in te]))[:, 1]
        res['char_ngram_lr'] = metrics(y[te], p_lr)
        hgb = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, max_leaf_nodes=63, class_weight='balanced', random_state=7)
        hgb.fit(F[tr], y[tr])
        p_hgb = hgb.predict_proba(F[te])[:, 1]
        res['lexical_hgb'] = metrics(y[te], p_hgb)
        sub = tr if len(tr) <= 150_000 else RNG.choice(tr, 150_000, replace=False)
        rf = RandomForestClassifier(n_estimators=120, min_samples_leaf=2, n_jobs=-1, class_weight='balanced', random_state=7)
        rf.fit(F[sub], y[sub])
        res['lexical_rf'] = metrics(y[te], rf.predict_proba(F[te])[:, 1])
        if blend:
            res['blend_mean'] = metrics(y[te], (p_lr + p_hgb) / 2)
        print(f'  [{name}]', {k: (v['f1'], v['pr_auc']) for k, v in res.items()})
        return res, (hv, lr, hgb)

    # 1. random stratified
    idx = np.arange(len(df))
    tr, te = train_test_split(idx, test_size=0.2, random_state=7, stratify=y)
    report['splits']['random_stratified'], _ = evaluate('random', tr, te)

    # 2. domain-grouped (no domain appears in both)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=7)
    tr, te = next(gss.split(idx, y, groups=df['reg']))
    report['splits']['domain_grouped'], models = evaluate('domain-grouped', tr, te)

    # 3. cross-source
    for a, b in (('ealvaradob', 'phiusiil'), ('phiusiil', 'ealvaradob')):
        tr = idx[df['source'].to_numpy() == a]
        te = idx[df['source'].to_numpy() == b]
        te = te if len(te) <= 60_000 else RNG.choice(te, 60_000, replace=False)
        report['splits'][f'cross_source_{a}_to_{b}'], _ = evaluate(f'{a}->{b}', tr, te)

    # ---- deployed model: blend on domain-grouped training fold, isotonic calibration on held-out fold ----
    gss = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=11)
    tr, cal = next(gss.split(idx, y, groups=df['reg']))
    hv, lr = fit_char_lr([urls[i] for i in tr], y[tr])
    hgb = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, max_leaf_nodes=63, class_weight='balanced', random_state=7)
    hgb.fit(F[tr], y[tr])
    p_cal = (lr.predict_proba(hv.transform([urls[i] for i in cal]))[:, 1] + hgb.predict_proba(F[cal])[:, 1]) / 2
    from sklearn.isotonic import IsotonicRegression
    iso = IsotonicRegression(out_of_bounds='clip').fit(p_cal, y[cal])
    report['calibration_fold'] = metrics(y[cal], iso.predict(p_cal))

    def predict(us: list[str]) -> np.ndarray:  # exactly the deployed scoring path: blend -> isotonic
        return iso.predict((lr.predict_proba(hv.transform(us))[:, 1] + hgb.predict_proba(feats(us))[:, 1]) / 2)
    report['fresh_feed'] = fresh_feed_eval(predict, seen_keys)
    print('fresh feed:', {k: v for k, v in report['fresh_feed'].items() if k not in ('confusion',)})
    out = S.models_dir / 'url'
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump({'n_features': N_FEATURES, 'lr': lr, 'hgb': hgb, 'iso': iso, 'feature_names': FEATURE_NAMES}, out / 'url_model.joblib', compress=3)
    report['deployed'] = 'blend(char_ngram_lr, lexical_hgb) + isotonic calibration, trained on domain-grouped split'
    report['seconds'] = round(time.time() - t0)
    (out / 'report.json').write_text(json.dumps(report, indent=1))
    register('url', report, out / 'url_model.joblib')
    print(json.dumps({k: {m: (v[m]['f1'], v[m]['pr_auc']) for m in v} for k, v in report['splits'].items()}, indent=1))
    print(f'done in {report["seconds"]}s')


if __name__ == '__main__':
    main()
