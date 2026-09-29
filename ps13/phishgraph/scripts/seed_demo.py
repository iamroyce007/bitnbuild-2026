"""Load (or with --clear, remove) the optional sample data (DEMO DATA) via the backend service.

Usage:  python scripts/seed_demo.py [--reset] [--clear]
  --reset  remove existing sample data first, then load it again
  --clear  remove all sample data and exit
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))

from app.database import init_db  # noqa: E402
from app.services import sample_data  # noqa: E402

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--reset', action='store_true')
    ap.add_argument('--clear', action='store_true')
    a = ap.parse_args()
    init_db()
    if a.clear or a.reset:
        print('cleared:', sample_data.clear())
    if not a.clear:
        r = asyncio.run(sample_data.load())
        print(f"loaded: {r['sample_detections']} sample detections; benign allowed {r.get('benign_allowed')}/12, phishing caught {r.get('phishing_caught')}/15")
