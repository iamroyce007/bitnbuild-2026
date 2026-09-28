"""Standalone worker process (used with REDIS_URL): consumes jobs from the Redis list and runs them.

    cd backend && python -m app.workers.run
Scale horizontally by starting more processes; each takes WORKER_CONCURRENCY jobs at a time.
"""
from __future__ import annotations

import asyncio
import json
import logging
import signal

from ..config import get_settings
from ..database import init_db
from ..utils.cache import get_cache
from .feed_collector import scheduler
from .queue import QUEUE_KEY, run_job

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s worker %(message)s')
log = logging.getLogger('worker')


async def main() -> None:
    init_db()
    r = get_cache().redis
    if r is None:
        raise SystemExit('REDIS_URL is not set or Redis is unreachable; the API runs jobs in-process without a separate worker.')
    sem = asyncio.Semaphore(get_settings().worker_concurrency)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    feeds = asyncio.create_task(scheduler())
    log.info('worker started (concurrency %s)', get_settings().worker_concurrency)

    async def handle(raw: str) -> None:
        async with sem:
            job = json.loads(raw)
            await run_job(job)
            get_cache().set(f'job:{job["id"]}', job, 86400)
            log.info('job %s %s -> %s', job['kind'], job['id'][:8], job['status'])

    while not stop.is_set():
        item = await asyncio.to_thread(r.blpop, [QUEUE_KEY], 2)
        if item:
            asyncio.create_task(handle(item[1]))
    feeds.cancel()
    log.info('worker stopped')


if __name__ == '__main__':
    asyncio.run(main())
