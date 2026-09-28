"""Measure real throughput and latency of a running API (fast path, no external enrichment).

    python scripts/load_test.py --n 400 --concurrency 16 [--api http://localhost:8000] [--key dev-local-key]
Reports requests/s and p50/p95/p99 latency for URL-only and full email analysis.
"""
from __future__ import annotations

import argparse
import asyncio
import random
import statistics
import time

import httpx

URLS = ['https://www.google.com/search?q={}', 'https://g00gle.com/login?s={}', 'https://sbi-kyc-update.online/verify?id={}', 'https://github.com/org/repo{}',
        'https://microsoft-login-security.example.xyz/verify?u={}', 'https://www.amazon.in/dp/B0{}', 'https://paypa1-billing.com/webscr?cmd=login&n={}']
EMAILS = [
    {'subject': 'Your account will be suspended {}', 'sender': 'Security <alert@secure-verify-{}.xyz>', 'body': 'Verify your identity within 24 hours at https://secure-verify-{}.xyz/login or lose access.'},
    {'subject': 'Lunch on Friday {}', 'sender': 'Priya <priya@annauniv.edu>', 'body': 'Hi all, lunch at 1pm. Agenda: https://docs.google.com/document/d/{}'},
    {'channel': 'sms', 'sender': '+9198765{}', 'body': 'Dear customer your KYC is pending, account blocked today. Share OTP {} to update.'},
]


def pct(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))]


async def run(kind: str, n: int, conc: int, api: str, key: str) -> None:
    lat: list[float] = []
    errors = 0
    sem = asyncio.Semaphore(conc)
    async with httpx.AsyncClient(base_url=api, headers={'X-API-Key': key}, timeout=60) as c:
        async def one(i: int) -> None:
            nonlocal errors
            async with sem:
                if kind == 'url':
                    body, path = {'url': random.choice(URLS).format(i)}, '/api/v1/analyze/url'
                else:
                    t = random.choice(EMAILS)
                    body, path = {k: (v.format(i) if isinstance(v, str) else v) for k, v in t.items()}, '/api/v1/analyze/email'
                t0 = time.perf_counter()
                r = await c.post(path, json=body)
                lat.append((time.perf_counter() - t0) * 1000)
                errors += r.status_code != 200
        t0 = time.perf_counter()
        await asyncio.gather(*(one(i) for i in range(n)))
        wall = time.perf_counter() - t0
    print(f'{kind:5s} n={n} concurrency={conc}: {n / wall:6.1f} req/s   p50 {statistics.median(lat):6.0f} ms   p95 {pct(lat, .95):6.0f} ms   '
          f'p99 {pct(lat, .99):6.0f} ms   errors {errors}')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--api', default='http://localhost:8000')
    ap.add_argument('--key', default='dev-local-key')
    ap.add_argument('--n', type=int, default=300)
    ap.add_argument('--concurrency', type=int, default=16)
    a = ap.parse_args()
    asyncio.run(run('url', a.n, a.concurrency, a.api, a.key))
    asyncio.run(run('email', a.n, a.concurrency, a.api, a.key))
