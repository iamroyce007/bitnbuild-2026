"""Download every external dataset PhishGraph uses, and record provenance (source, licence, date, sha256, counts)
in data/DATASETS.lock.json. Nothing is downloaded that is not listed here.

    python scripts/download_datasets.py                  # everything (training + reference)
    python scripts/download_datasets.py --reference-only # only what the running service needs (Tranco, PSL, confusables)
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import time
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / 'data' / 'raw'

SOURCES = [
    # reference data needed at runtime
    {'name': 'tranco-top-1m', 'kind': 'reference', 'url': 'https://tranco-list.eu/top-1m.csv.zip', 'file': 'top-1m.csv', 'unzip': True,
     'license': 'Tranco list, free for research and commercial use (see tranco-list.eu)'},
    {'name': 'public-suffix-list', 'kind': 'reference', 'url': 'https://raw.githubusercontent.com/publicsuffix/list/main/public_suffix_list.dat',
     'file': 'public_suffix_list.dat', 'license': 'MPL-2.0'},
    {'name': 'unicode-confusables', 'kind': 'reference', 'url': 'https://www.unicode.org/Public/security/latest/confusables.txt',
     'file': 'confusables.txt', 'license': 'Unicode License v3'},
    # training data
    {'name': 'ealvaradob-phishing-texts', 'kind': 'training', 'url': 'https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/main/texts.json',
     'file': 'texts.json', 'license': 'Apache-2.0'},
    {'name': 'ealvaradob-phishing-urls', 'kind': 'training', 'url': 'https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/main/urls.json',
     'file': 'urls.json', 'license': 'Apache-2.0'},
    {'name': 'phiusiil-url', 'kind': 'training', 'url': 'https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip',
     'file': 'PhiUSIIL_Phishing_URL_Dataset.csv', 'unzip': True, 'license': 'CC BY 4.0 (UCI ML Repository #967)'},
    {'name': 'zefang-phishing-email', 'kind': 'training', 'url': 'https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/resolve/main/Phishing_Email.csv',
     'file': 'phishing_email.csv', 'license': 'LGPL-3.0'},
]


def fetch(url: str, tries: int = 4) -> bytes:
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'PhishGraph dataset fetcher'}), timeout=600) as r:
                return r.read()
        except Exception as e:  # flaky networks: retry with backoff
            if i == tries - 1:
                raise
            print(f'  retry {i + 1} for {url}: {e}')
            time.sleep(2 ** i)
    raise RuntimeError('unreachable')


def count(path: Path) -> dict:
    if path.suffix == '.json':
        d = json.loads(path.read_text())
        labels: dict = {}
        for x in d:
            labels[str(x.get('label'))] = labels.get(str(x.get('label')), 0) + 1
        return {'rows': len(d), 'labels': labels}
    with open(path, 'rb') as f:
        return {'lines': sum(1 for _ in f)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--reference-only', action='store_true')
    ap.add_argument('--embeddings', action='store_true', help='also fetch the MiniLM sentence-embedding model')
    a = ap.parse_args()
    RAW.mkdir(parents=True, exist_ok=True)
    lock = []
    for s in SOURCES:
        if a.reference_only and s['kind'] != 'reference':
            continue
        dest = RAW / s['file']
        if not dest.exists():
            print(f'downloading {s["name"]} ...')
            data = fetch(s['url'])
            if s.get('unzip'):
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    member = next(n for n in z.namelist() if n.endswith(s['file']))
                    dest.write_bytes(z.read(member))
            else:
                dest.write_bytes(data)
        sha = hashlib.sha256(dest.read_bytes()).hexdigest()
        lock.append({**{k: s[k] for k in ('name', 'kind', 'url', 'license')}, 'file': str(dest.relative_to(ROOT)), 'sha256': sha,
                     'bytes': dest.stat().st_size, 'downloaded': time.strftime('%Y-%m-%d'), **count(dest)})
        print(f'  {s["name"]}: {dest.stat().st_size / 1e6:.1f} MB sha256 {sha[:16]}')
    if a.embeddings:
        from huggingface_hub import snapshot_download
        snapshot_download('sentence-transformers/all-MiniLM-L6-v2', local_dir=str(ROOT / 'models' / 'all-MiniLM-L6-v2'),
                          allow_patterns=['*.json', '*.txt', '*.safetensors', '1_Pooling/*'])
        lock.append({'name': 'all-MiniLM-L6-v2', 'kind': 'model', 'url': 'https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2', 'license': 'Apache-2.0'})
    (ROOT / 'data' / 'DATASETS.lock.json').write_text(json.dumps(lock, indent=1))
    print(f'wrote data/DATASETS.lock.json ({len(lock)} entries)')


if __name__ == '__main__':
    main()
