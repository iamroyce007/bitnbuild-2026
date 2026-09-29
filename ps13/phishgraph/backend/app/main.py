"""PhishGraph API entry point: app factory, lifespan (migrations, model preload, workers, schedulers), health,
metrics, WebSocket event stream, and the built dashboard served as static files."""
from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .api import routes_analyze, routes_data
from .api.deps import METRICS, resolve_client
from .config import ROOT, get_settings
from .database import init_db
from .services.events import bus

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
log = logging.getLogger('phishgraph')
STATE = {'ready': False, 'warmup_s': None}


def _warm() -> None:
    t = time.time()
    from .services.brand_engine import get_brand_engine
    from .services.intel_store import get_intel_store
    from .services.nlp_engine import get_nlp_engine
    from .services.url_engine import get_url_engine
    get_brand_engine()
    get_url_engine().analyze('https://example.com/')
    get_nlp_engine().analyze('warm up the models')
    get_intel_store().load()
    STATE['warmup_s'] = round(time.time() - t, 1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    await asyncio.to_thread(_warm)
    tasks = []
    if os.environ.get('SERVERLESS'):  # no background work survives a serverless response: jobs run inline instead
        STATE['ready'] = True
        yield
        return
    from .workers.queue import get_queue
    get_queue().start()
    from .workers.feed_collector import scheduler
    tasks.append(asyncio.create_task(scheduler()))
    from .connectors.mailboxes import configured_sources, mailbox_loop
    if configured_sources():
        tasks.append(asyncio.create_task(mailbox_loop()))
    STATE['ready'] = True
    log.info('PhishGraph ready (warm-up %ss)', STATE['warmup_s'])
    yield
    for t in tasks:
        t.cancel()
    from .services.graph_store import get_graph_store
    get_graph_store().save()


app = FastAPI(title='PhishGraph API', version='1.0.0', lifespan=lifespan,
              description='Autonomous real-time phishing intelligence, graph detection & response. Authenticate with the X-API-Key header.')
s = get_settings()
app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in s.cors_origins.split(',') if o.strip()],
                   allow_origin_regex=r'^chrome-extension://[a-p]{32}$', allow_methods=['*'], allow_headers=['*'])


@app.middleware('http')
async def metrics_mw(request: Request, call_next):
    t = time.perf_counter()
    route = request.url.path if not request.url.path.startswith('/api/v1/detection/') else '/api/v1/detection/{id}'
    try:
        resp = await call_next(request)
    except Exception:
        METRICS['errors'][route] += 1
        log.exception('unhandled error on %s', route)
        return JSONResponse({'detail': 'internal error'}, status_code=500)
    METRICS['requests'][route] += 1
    METRICS['latency_ms_sum'][route] += (time.perf_counter() - t) * 1000
    if resp.status_code >= 500:
        METRICS['errors'][route] += 1
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    return resp


app.include_router(routes_analyze.router)
app.include_router(routes_data.router)


@app.get('/health', tags=['ops'])
def health():
    return {'status': 'ok', 'uptime_s': round(time.time() - METRICS['started'])}


@app.get('/ready', tags=['ops'])
def ready():
    from .services.graph_store import get_graph_store
    from .utils.cache import get_cache
    from .workers.queue import get_queue
    body = {'ready': STATE['ready'], 'warmup_s': STATE['warmup_s'], 'database': get_settings().database_url.split(':', 1)[0],
            'cache': get_cache().backend, 'graph': get_graph_store().backend, 'queue_depth': get_queue().depth()}
    return JSONResponse(body, status_code=200 if STATE['ready'] else 503)


@app.get('/metrics', tags=['ops'], response_class=PlainTextResponse)
def metrics():
    from .services.threat_intel import get_ti
    from .workers.queue import get_queue
    lines = ['# TYPE phishgraph_requests_total counter']
    for r, n in METRICS['requests'].items():
        lines.append(f'phishgraph_requests_total{{route="{r}"}} {n}')
        lines.append(f'phishgraph_request_latency_ms_avg{{route="{r}"}} {METRICS["latency_ms_sum"][r] / max(n, 1):.1f}')
    for r, n in METRICS['errors'].items():
        lines.append(f'phishgraph_errors_total{{route="{r}"}} {n}')
    for d, n in METRICS['detections'].items():
        lines.append(f'phishgraph_detections_total{{decision="{d}"}} {n}')
    if METRICS['inference_count']:
        lines.append(f'phishgraph_inference_ms_avg {METRICS["inference_ms_sum"] / METRICS["inference_count"]:.1f}')
    q = get_queue()
    lines += [f'phishgraph_queue_depth {q.depth()}', f'phishgraph_jobs_processed_total {q.processed}', f'phishgraph_jobs_failed_total {q.failed}']
    for p in get_ti().health():
        lines.append(f'phishgraph_provider_calls_total{{provider="{p["name"]}"}} {p["calls"]}')
        lines.append(f'phishgraph_provider_errors_total{{provider="{p["name"]}"}} {p["errors"]}')
        if p['avg_latency_ms'] is not None:
            lines.append(f'phishgraph_provider_latency_ms_avg{{provider="{p["name"]}"}} {p["avg_latency_ms"]}')
    return '\n'.join(lines) + '\n'


@app.websocket('/api/v1/events')
async def events(ws: WebSocket):
    key = ws.query_params.get('api_key') or ws.headers.get('x-api-key')
    if not resolve_client(key):
        await ws.close(code=4401)
        return
    await ws.accept()
    q = bus.subscribe()
    try:
        await ws.send_json({'event': 'hello', 'recent': bus.recent[-30:]})
        while True:
            try:
                msg = await asyncio.wait_for(q.get(), timeout=25)
                await ws.send_json(msg)
            except asyncio.TimeoutError:
                await ws.send_json({'event': 'ping'})
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        bus.unsubscribe(q)


@app.get('/api/v1/events/recent', tags=['ops'])
def recent_events(since: str = ''):
    """Polling fallback for environments without WebSockets (e.g. serverless)."""
    return [e for e in bus.recent if not since or str(e.get('at', '')) > since][-50:]


# built dashboard: frontend/dist (local/Docker) or static/ (bundled into the Vercel function by scripts/deploy_vercel.sh)
_EXT_ZIP: bytes | None = None


@app.get('/downloads/phishgraph-extension.zip', include_in_schema=False)
def extension_zip():
    """The Chrome extension as a ready-to-unpack zip (built on first request from the extension/ folder)."""
    import io
    import zipfile
    from fastapi.responses import Response
    global _EXT_ZIP
    if _EXT_ZIP is None:
        src = ROOT / 'extension'
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            for f in sorted(src.rglob('*')):
                if f.is_file() and not f.name.startswith('.'):
                    z.write(f, f'phishgraph-extension/{f.relative_to(src)}')
        _EXT_ZIP = buf.getvalue()
    return Response(_EXT_ZIP, media_type='application/zip', headers={'Content-Disposition': 'attachment; filename="phishgraph-extension.zip"'})


DIST = next((d for d in (ROOT / 'frontend' / 'dist', ROOT / 'static') if (d / 'index.html').exists()), ROOT / 'frontend' / 'dist')
if (DIST / 'index.html').exists():
    app.mount('/assets', StaticFiles(directory=DIST / 'assets'), name='assets')

    @app.get('/{path:path}', include_in_schema=False)
    def spa(path: str):
        f = DIST / path
        if path and f.is_file() and DIST in f.resolve().parents:
            return FileResponse(f)
        return FileResponse(DIST / 'index.html')
