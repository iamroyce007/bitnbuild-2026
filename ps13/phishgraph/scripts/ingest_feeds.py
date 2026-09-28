"""Run the threat-feed collectors once (OpenPhish community feed; PhishTank / URLhaus when keys are set).

    python scripts/ingest_feeds.py
"""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from app.database import init_db  # noqa: E402
from app.workers.feed_collector import refresh_all  # noqa: E402

if __name__ == '__main__':
    init_db()
    print(json.dumps(asyncio.run(refresh_all()), indent=1, default=str))
