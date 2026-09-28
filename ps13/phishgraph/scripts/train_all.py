"""Retrain both models and evaluate the look-alike engine. Human-approved: run it deliberately after reviewing the
feedback queue (data/processed/hard_negatives.jsonl, confirmed_phishing.jsonl). Each run is versioned in models/registry.json.

    python scripts/train_all.py [--skip-url] [--skip-email] [--skip-lookalike]
"""
from __future__ import annotations

import argparse
import runpy
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--skip-url', action='store_true')
    ap.add_argument('--skip-email', action='store_true')
    ap.add_argument('--skip-lookalike', action='store_true')
    a = ap.parse_args()
    env_py = sys.executable
    if not a.skip_url:
        subprocess.run([env_py, '-m', 'app.ml.train_url'], cwd=ROOT / 'backend', check=True)
    if not a.skip_email:
        subprocess.run([env_py, '-m', 'app.ml.train_email'], cwd=ROOT / 'backend', check=True)
    if not a.skip_lookalike:
        runpy.run_path(str(ROOT / 'scripts' / 'eval_lookalike.py'), run_name='__main__')
    print('done: see models/registry.json and data/processed/lookalike_eval.json')


if __name__ == '__main__':
    main()
