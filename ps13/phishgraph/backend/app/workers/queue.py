"""Background job queue.

In-process asyncio worker pool by default (no extra services). With REDIS_URL set, jobs are pushed to a
Redis list and consumed by `python -m app.workers.run` processes, so API and workers scale independently.
Jobs: deepen (enrich + external TI + re-score), investigate (unknown URL), refresh_feeds, drift_snapshot.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid

from ..config import get_settings
from ..utils.cache import get_cache

log = logging.getLogger(__name__)
QUEUE_KEY = 'phishgraph:jobs'


class JobQueue:
    def __init__(self) -> None:
        self.q: asyncio.Queue | None = None
        self.workers: list[asyncio.Task] = []
        self.jobs: dict[str, dict] = {}
        self.processed = 0
        self.failed = 0
        self.redis = get_cache().redis

    def start(self, loop_workers: int | None = None) -> None:
        if self.q is not None:
            return
        self.q = asyncio.Queue(maxsize=5000)
        for i in range(loop_workers or get_settings().worker_concurrency):
            self.workers.append(asyncio.create_task(self._worker(i)))

    def submit(self, kind: str, payload: dict) -> str:
        jid = str(uuid.uuid4())
        job = {'id': jid, 'kind': kind, 'payload': payload, 'status': 'queued', 'created': time.time(), 'result': None, 'error': None}
        self.jobs[jid] = job
        if len(self.jobs) > 5000:
            for k in list(self.jobs)[:1000]:
                self.jobs.pop(k, None)
        if self.redis:
            self.redis.rpush(QUEUE_KEY, json.dumps(job))
            get_cache().set(f'job:{jid}', job, 86400)
        elif self.q is not None:
            try:
                self.q.put_nowait(job)
            except asyncio.QueueFull:
                job['status'] = 'rejected'
        else:
            job['status'] = 'no-worker'
        return jid

    @property
    def has_worker(self) -> bool:
        return self.q is not None or self.redis is not None

    async def submit_or_run(self, kind: str, payload: dict) -> str:
        """Queue the job, or run it inline when no worker exists (serverless deployments)."""
        if self.has_worker:
            return self.submit(kind, payload)
        jid = str(uuid.uuid4())
        job = {'id': jid, 'kind': kind, 'payload': payload, 'status': 'queued', 'created': time.time(), 'result': None, 'error': None}
        self.jobs[jid] = job
        await run_job(job, self)
        return jid

    def status(self, jid: str) -> dict | None:
        return self.jobs.get(jid) or get_cache().get(f'job:{jid}')

    def depth(self) -> int:
        if self.redis:
            try:
                return int(self.redis.llen(QUEUE_KEY))
            except Exception:
                return -1
        return self.q.qsize() if self.q else 0

    async def _worker(self, i: int) -> None:
        while True:
            job = await self.q.get()
            await run_job(job, self)
            self.q.task_done()


async def run_job(job: dict, queue: JobQueue | None = None) -> None:
    from ..services import pipeline
    from ..services.investigation import investigate
    job['status'] = 'running'
    try:
        if job['kind'] == 'deepen':
            r = await pipeline.deepen(job['payload']['detection_id'])
            job['result'] = {'risk': r['risk_score'], 'decision': r['decision']} if r else None
        elif job['kind'] == 'investigate':
            job['result'] = await investigate(job['payload']['url'])
        elif job['kind'] == 'refresh_feeds':
            from .feed_collector import refresh_all
            job['result'] = await refresh_all()
        else:
            raise ValueError(f'unknown job {job["kind"]}')
        job['status'] = 'done'
        if queue:
            queue.processed += 1
    except Exception as e:
        log.exception('job %s failed', job['kind'])
        job['status'] = 'failed'
        job['error'] = f'{type(e).__name__}: {e}'[:300]
        if queue:
            queue.failed += 1
    if queue and queue.redis:
        get_cache().set(f'job:{job["id"]}', job, 86400)


_q: JobQueue | None = None


def get_queue() -> JobQueue:
    global _q
    if _q is None:
        _q = JobQueue()
    return _q
