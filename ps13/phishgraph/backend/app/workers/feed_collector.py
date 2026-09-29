"""Scheduled threat-feed ingestion into the local IOC store. Feeds are never queried synchronously per message.

  openphish  community feed (free, no key, ~12 h refresh upstream)
  phishtank  online-valid.json (needs PHISHTANK_APP_KEY)
  urlhaus    recent URLs CSV (Auth-Key if configured)
Each run records counts and status; failures are reported, never silently ignored.
"""
from __future__ import annotations

import asyncio
import csv
import io
import logging
import time

import httpx

from ..config import get_settings
from ..services.intel_store import get_intel_store

log = logging.getLogger(__name__)
STATUS: dict[str, dict] = {}


async def _get(url: str, headers: dict | None = None) -> httpx.Response:
    async with httpx.AsyncClient(timeout=60, follow_redirects=True, headers={'user-agent': 'PhishGraph/1.0 feed collector', **(headers or {})}) as c:
        r = await c.get(url)
        r.raise_for_status()
        return r


async def collect_openphish() -> dict:
    r = await _get('https://openphish.com/feed.txt')
    urls = [u.strip() for u in r.text.splitlines() if u.strip().startswith('http')]
    n = get_intel_store().add([('url', u) for u in urls], source='openphish', tags=['phishing'])
    return {'fetched': len(urls), 'new': n}


async def collect_phishtank() -> dict:
    key = get_settings().phishtank_app_key
    if not key:
        return {'status': 'not_configured'}
    r = await _get(f'https://data.phishtank.com/data/{key}/online-valid.json')
    items = r.json()
    n = get_intel_store().add([('url', i['url']) for i in items if i.get('url')], source='phishtank', tags=['phishing', 'verified'])
    return {'fetched': len(items), 'new': n}


async def collect_urlhaus() -> dict:
    s = get_settings()
    r = await _get('https://urlhaus.abuse.ch/downloads/csv_recent/', headers={'Auth-Key': s.urlhaus_auth_key} if s.urlhaus_auth_key else None)
    rows = [row for row in csv.reader(io.StringIO(r.text)) if row and not row[0].startswith('#')]
    urls = [row[2] for row in rows if len(row) > 3 and row[3] == 'online']
    n = get_intel_store().add([('url', u) for u in urls], source='urlhaus', tags=['malware'])
    return {'fetched': len(urls), 'new': n}


COLLECTORS = {'openphish': collect_openphish, 'phishtank': collect_phishtank, 'urlhaus': collect_urlhaus}


async def run_one(name: str) -> dict:
    t = time.time()
    try:
        res = await COLLECTORS[name]()
        STATUS[name] = {'status': res.get('status', 'ok'), 'at': time.time(), 'seconds': round(time.time() - t, 1), **res}
    except Exception as e:
        STATUS[name] = {'status': 'error', 'at': time.time(), 'error': f'{type(e).__name__}: {e}'[:200]}
    return STATUS[name]


async def refresh_all() -> dict:
    return {name: await run_one(name) for name in COLLECTORS}


async def scheduler() -> None:
    """Runs forever inside the API/worker process when ENABLE_EXTERNAL_TI is on."""
    await asyncio.sleep(5)
    while True:
        await refresh_all()  # OpenPhish needs no key; keyed feeds report not_configured
        await asyncio.sleep(max(5, get_settings().feed_refresh_minutes) * 60)
