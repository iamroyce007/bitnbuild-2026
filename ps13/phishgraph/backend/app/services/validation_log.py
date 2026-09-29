"""History of validation runs (feature checks, fresh-feed evaluations, look-alike evaluations), so the dashboard can show
how the system was tested over time next to the model training history in models/registry.json.

The file lives in the repository (data/validation/history.json) and is deployed with it, so the public demo shows the
same history. Every entry is written by a script that actually ran; nothing here is typed in by hand.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from ..config import ROOT

PATH = ROOT / 'data' / 'validation' / 'history.json'
KEEP = 200


def load() -> list[dict]:
    try:
        return json.loads(PATH.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return []


def append(kind: str, summary: dict, details: dict | None = None, target: str = '') -> dict:
    """kind: feature_check | fresh_feed | lookalike. `summary` is small (shown in lists); `details` holds rows."""
    runs = load()
    entry = {'id': f'{kind}-{time.strftime("%Y%m%d-%H%M%S")}', 'kind': kind, 'at': time.strftime('%Y-%m-%dT%H:%M:%S'),
             'target': target, 'summary': summary, 'details': details or {}}
    runs.append(entry)
    PATH.parent.mkdir(parents=True, exist_ok=True)
    PATH.write_text(json.dumps(runs[-KEEP:], indent=1, ensure_ascii=False), encoding='utf-8')
    return entry


def path() -> Path:
    return PATH
