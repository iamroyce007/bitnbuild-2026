"""Minimal file-based model registry: every training run is versioned with its metrics and artifact hash."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from ..config import get_settings

REG = get_settings().models_dir / 'registry.json'


def _load() -> dict:
    return json.loads(REG.read_text()) if REG.exists() else {'models': []}


def register(name: str, report: dict, artifact: Path, status: str = 'active') -> dict:
    reg = _load()
    sha = hashlib.sha256(artifact.read_bytes()).hexdigest()[:16] if artifact.exists() else None
    version = 1 + max((m['version'] for m in reg['models'] if m['name'] == name), default=0)
    for m in reg['models']:
        if m['name'] == name and m['status'] == 'active':
            m['status'] = 'archived'
    entry = {'name': name, 'version': version, 'status': status, 'trained_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
             'artifact': str(artifact.relative_to(get_settings().models_dir)), 'sha256_16': sha, 'report': report}
    reg['models'].append(entry)
    REG.write_text(json.dumps(reg, indent=1))
    return entry


def active(name: str) -> dict | None:
    return next((m for m in reversed(_load()['models']) if m['name'] == name and m['status'] == 'active'), None)


def all_models() -> list[dict]:
    return _load()['models']
