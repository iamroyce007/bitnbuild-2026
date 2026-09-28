"""Analysis endpoints: email (JSON / raw / .eml upload), URL, and asynchronous investigation."""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse

from ..models.schemas import AnalysisOut, EmailIn, InvestigateIn, URLIn
from ..services.email_parser import ParsedMessage, parse_json_message, parse_raw_email
from ..services.pipeline import analyze
from ..services.url_extractor import ExtractedURL
from ..utils.url_utils import parse_url, ssrf_block_reason
from ..workers.queue import get_queue
from .deps import METRICS, audit, require_key

router = APIRouter(prefix='/api/v1', tags=['analyze'])


def _out(r: dict) -> dict:
    METRICS['detections'][r['decision']] += 1
    METRICS['inference_ms_sum'] += r['latency_ms']
    METRICS['inference_count'] += 1
    return {'detection_id': r['detection_id'], 'risk_score': r['risk_score'], 'decision': r['decision'], 'scores': r['scores'], 'reasons': r['reasons'],
            'urls': r['urls'], 'campaign': r['campaign'], 'conflicting_intelligence': r['conflicting_intelligence'], 'latency_ms': r['latency_ms'], 'report': r}


@router.post('/analyze/email', response_model=AnalysisOut, summary='Analyse an email / SMS / WhatsApp message')
async def analyze_email(body: EmailIn, request: Request, who: str = Depends(require_key)):
    pm = parse_raw_email(body.raw) if body.raw else parse_json_message(body.subject, body.sender, body.body, body.html, body.channel, body.reply_to, body.headers)
    if body.channel != 'email' and not body.raw:
        pm.channel = body.channel
    r = await analyze(pm, source=f'api:{who}', deep=body.deep)
    return _out(r)


@router.post('/analyze/eml', response_model=AnalysisOut, summary='Upload a .eml file')
async def analyze_eml(file: UploadFile = File(...), deep: bool = False, who: str = Depends(require_key)):
    data = await file.read()
    if len(data) > 10_000_000:
        raise HTTPException(413, 'file too large (10 MB max)')
    r = await analyze(parse_raw_email(data), source=f'api:{who}', deep=deep)
    return _out(r)


@router.post('/analyze/url', response_model=AnalysisOut, summary='Analyse a single URL (fast, local)')
async def analyze_url(body: URLIn, who: str = Depends(require_key)):
    p = parse_url(body.url)
    if p is None:
        raise HTTPException(422, 'not a valid URL')
    pm = ParsedMessage(channel='url', text='', urls=[ExtractedURL(p, ['api'])])
    r = await analyze(pm, source=f'api:{who}', deep=body.deep, kind='url')
    return _out(r)


@router.post('/investigate', status_code=202, summary='Investigate an unknown URL (async full chain); poll /jobs/{id}')
async def investigate(body: InvestigateIn, request: Request, who: str = Depends(require_key)):
    p = parse_url(body.url)
    if p is None or not p.host:
        raise HTTPException(422, 'not a valid http(s) URL')
    why = ssrf_block_reason(p.host)
    if why:
        audit(who, 'investigate.refused', body.url, {'reason': why}, request.client.host if request.client else '')
        raise HTTPException(400, f'refused by SSRF protection: {why}')
    jid = get_queue().submit('investigate', {'url': p.normalized})
    audit(who, 'investigate.submit', p.normalized, {'job': jid}, request.client.host if request.client else '')
    return JSONResponse({'job_id': jid, 'status': 'queued', 'poll': f'/api/v1/jobs/{jid}'}, status_code=202)


@router.get('/jobs/{job_id}', summary='Background job status/result')
async def job(job_id: str, who: str = Depends(require_key)):
    j = get_queue().status(job_id)
    if not j:
        raise HTTPException(404, 'unknown job')
    return j
