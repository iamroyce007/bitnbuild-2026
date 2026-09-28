"""Request/response schemas (OpenAPI)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class EmailIn(BaseModel):
    subject: str = Field('', max_length=2000)
    sender: str = Field('', max_length=400, description='"Name <addr@domain>" or an address / SMS sender id')
    body: str = Field('', max_length=200_000)
    html: str = Field('', max_length=500_000)
    reply_to: str = Field('', max_length=400)
    channel: Literal['email', 'sms', 'whatsapp', 'other'] = 'email'
    headers: dict[str, str] | None = None
    raw: str | None = Field(None, max_length=2_000_000, description='Full RFC 822 message; overrides the other fields')
    deep: bool = Field(False, description='Wait for DNS/RDAP/TLS/ASN enrichment and external threat intel before answering')

    model_config = {'json_schema_extra': {'example': {
        'subject': 'Your Microsoft account will be suspended', 'sender': 'Microsoft Security <security@microsoft-support-alert.xyz>',
        'body': 'Unusual sign-in detected. Verify your identity within 24 hours at https://microsoft-login-security.example.xyz/verify'}}}


class URLIn(BaseModel):
    url: str = Field(..., max_length=4000)
    deep: bool = False


class InvestigateIn(BaseModel):
    url: str = Field(..., max_length=4000)


class FeedbackIn(BaseModel):
    detection_id: str
    label: Literal['confirmed_phishing', 'false_positive', 'unsure']
    note: str = Field('', max_length=2000)


class IOCIn(BaseModel):
    ioc_type: Literal['url', 'domain', 'ip', 'hash']
    value: str = Field(..., max_length=4000)
    tags: list[str] = []


class AnalysisOut(BaseModel):
    detection_id: str
    risk_score: float
    decision: Literal['ALLOW', 'FLAG', 'QUARANTINE', 'BLOCK']
    scores: dict[str, float | None]
    reasons: list[dict]
    urls: list[dict]
    campaign: dict | None
    conflicting_intelligence: bool
    latency_ms: int
    report: dict
