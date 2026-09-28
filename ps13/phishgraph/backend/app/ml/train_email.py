"""Train and evaluate the two-stage email NLP models.

Stage 1 (fast):     hashed word uni/bi-gram TF-IDF + Logistic Regression (explainable token weights)
Stage 2 (semantic): all-MiniLM-L6-v2 sentence embeddings + Logistic Regression (catches paraphrases)

Sources (1 = phishing):
  A  ealvaradob/phishing-dataset texts.json (emails + SMS, Apache-2.0)
  B  zefang-liu/phishing-email-dataset Phishing_Email.csv (LGPL-3.0)
Exact duplicates across sources are removed before any split. Splits: random stratified, and
cross-source in both directions (the honest number; random splits over-state accuracy because
corpora carry source artifacts such as Enron signatures).

Run:  python -m app.ml.train_email
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import HashingVectorizer, TfidfTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline

from ..config import get_settings
from ..services.nlp_features import word_features
from .model_registry import register
from .train_url import metrics

S = get_settings()
RAW = S.data_dir / 'raw'
N_FEATURES = 2 ** 20


def load() -> pd.DataFrame:
    a = pd.read_json(RAW / 'texts.json').rename(columns={'text': 'text'})
    a['source'] = 'ealvaradob'
    csv.field_size_limit(sys.maxsize)
    rows = []
    with open(RAW / 'phishing_email.csv', encoding='utf-8', errors='replace', newline='') as f:
        r = csv.reader(f)
        next(r)
        for row in r:
            if len(row) >= 3 and row[2] in ('Safe Email', 'Phishing Email'):
                rows.append((row[1], 1 if row[2] == 'Phishing Email' else 0))
    b = pd.DataFrame(rows, columns=['text', 'label'])
    b['source'] = 'zefang'
    df = pd.concat([a, b], ignore_index=True)
    df['text'] = df['text'].astype(str)
    df = df[df['text'].str.len() > 20]
    df['h'] = [hashlib.md5(re.sub(r'\W+', ' ', t.lower()).strip()[:2000].encode()).hexdigest() for t in df['text']]
    n0 = len(df)
    df = df.drop_duplicates('h')
    print(f'{n0} -> {len(df)} after cross-source exact-dup removal\n{df.groupby(["source", "label"]).size()}')
    return df.reset_index(drop=True)


def tfidf_lr():
    return make_pipeline(HashingVectorizer(analyzer=word_features, n_features=N_FEATURES, alternate_sign=False, norm=None),
                         TfidfTransformer(sublinear_tf=True), LogisticRegression(C=8.0, max_iter=1000, solver='liblinear', class_weight='balanced'))


def embed(texts: list[str]) -> np.ndarray:
    from sentence_transformers import SentenceTransformer
    m = SentenceTransformer(S.embedding_model)
    return m.encode([t[:1500] for t in texts], batch_size=64, normalize_embeddings=True, show_progress_bar=False)


def main() -> None:
    t0 = time.time()
    df = load()
    y = df['label'].to_numpy()
    X = df['text'].tolist()
    src = df['source'].to_numpy()
    idx = np.arange(len(df))
    report = {'data': {'n': int(len(df)), 'by_source': df.groupby('source').size().to_dict(), 'phishing_ratio': round(float(y.mean()), 4)}, 'splits': {}}

    print('embedding all texts with MiniLM...')
    E = embed(X)
    print(f'embeddings {E.shape} in {time.time() - t0:.0f}s')

    def run(name, tr, te):
        res = {}
        m = tfidf_lr().fit([X[i] for i in tr], y[tr])
        p1 = m.predict_proba([X[i] for i in te])[:, 1]
        res['tfidf_lr'] = metrics(y[te], p1)
        e = LogisticRegression(C=4.0, max_iter=2000, class_weight='balanced').fit(E[tr], y[tr])
        p2 = e.predict_proba(E[te])[:, 1]
        res['minilm_lr'] = metrics(y[te], p2)
        res['blend'] = metrics(y[te], (p1 + p2) / 2)
        print(f'  [{name}]', {k: (v['f1'], v['pr_auc']) for k, v in res.items()})
        return res

    tr, te = train_test_split(idx, test_size=0.2, random_state=7, stratify=y)
    report['splits']['random_stratified'] = run('random', tr, te)
    for a, b in (('ealvaradob', 'zefang'), ('zefang', 'ealvaradob')):
        if (src == a).sum() >= 500 and (src == b).sum() >= 500:
            report['splits'][f'cross_source_{a}_to_{b}'] = run(f'{a}->{b}', idx[src == a], idx[src == b])
    report['notes'] = []
    if (src == 'zefang').sum() < 500:
        report['notes'].append('zefang-liu/phishing-email-dataset is fully contained in ealvaradob/phishing-dataset (exact duplicates after '
                               'normalisation), so a cross-source split between them is not meaningful; cross-channel splits are reported instead.')
    # cross-channel shift: short messages (SMS-like) vs long messages (email-like)
    ch = np.where(df['text'].str.len().to_numpy() <= 320, 'sms', 'email')
    report['data']['by_channel'] = {k: int((ch == k).sum()) for k in ('sms', 'email')}
    for a, b in (('email', 'sms'), ('sms', 'email')):
        tr_i, te_i = idx[ch == a], idx[ch == b]
        if len(np.unique(y[tr_i])) == 2 and len(np.unique(y[te_i])) == 2:
            report['splits'][f'cross_channel_{a}_to_{b}'] = run(f'{a}->{b}', tr_i, te_i)

    # deployed: both stages on all data
    stage1 = tfidf_lr().fit(X, y)
    stage2 = LogisticRegression(C=4.0, max_iter=2000, class_weight='balanced').fit(E, y)
    out = S.models_dir / 'email'
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump({'stage1': stage1, 'stage2': stage2}, out / 'email_model.joblib', compress=3)
    # phishing exemplar bank for semantic campaign similarity (centroids of k-means over phishing embeddings)
    from sklearn.cluster import MiniBatchKMeans
    ph = E[y == 1]
    km = MiniBatchKMeans(n_clusters=64, random_state=7, n_init=3).fit(ph)
    np.save(out / 'phish_centroids.npy', km.cluster_centers_ / np.linalg.norm(km.cluster_centers_, axis=1, keepdims=True))
    report['deployed'] = 'stage1 hashed TF-IDF LR + stage2 MiniLM-embedding LR, averaged; trained on all de-duplicated data'
    report['seconds'] = round(time.time() - t0)
    (out / 'report.json').write_text(json.dumps(report, indent=1))
    register('email', report, out / 'email_model.joblib')
    print(json.dumps({k: {m: (v[m]['f1'], v[m]['pr_auc']) for m in v} for k, v in report['splits'].items()}, indent=1))


if __name__ == '__main__':
    main()
