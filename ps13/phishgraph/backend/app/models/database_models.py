"""Relational schema (PostgreSQL / SQLite). The relationship graph itself lives in the graph store (Neo4j / NetworkX)."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    role: Mapped[str] = mapped_column(String(20), default='analyst')  # analyst | admin | ingest
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Email(Base):
    __tablename__ = 'emails'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    channel: Mapped[str] = mapped_column(String(16), default='email', index=True)
    message_id: Mapped[str] = mapped_column(String(300), default='')
    sender: Mapped[str] = mapped_column(String(320), default='', index=True)
    sender_domain: Mapped[str] = mapped_column(String(255), default='', index=True)
    sender_name: Mapped[str] = mapped_column(String(300), default='')
    subject: Mapped[str] = mapped_column(String(1000), default='')
    body_excerpt: Mapped[str] = mapped_column(Text, default='')
    auth: Mapped[dict] = mapped_column(JSON, default=dict)
    attachments: Mapped[list] = mapped_column(JSON, default=list)
    source: Mapped[str] = mapped_column(String(40), default='api')  # api | imap | gmail | msgraph | demo
    demo: Mapped[bool] = mapped_column(Boolean, default=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class URLRecord(Base):
    __tablename__ = 'urls'
    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(Text)
    url_hash: Mapped[str] = mapped_column(String(64), unique=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    registrable: Mapped[str] = mapped_column(String(255), index=True)
    risk: Mapped[float] = mapped_column(Float, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    times_seen: Mapped[int] = mapped_column(Integer, default=1)


class EmailURL(Base):
    __tablename__ = 'email_urls'
    id: Mapped[int] = mapped_column(primary_key=True)
    email_id: Mapped[str] = mapped_column(ForeignKey('emails.id', ondelete='CASCADE'), index=True)
    url_id: Mapped[int] = mapped_column(ForeignKey('urls.id', ondelete='CASCADE'), index=True)
    sources: Mapped[list] = mapped_column(JSON, default=list)


class Domain(Base):
    __tablename__ = 'domains'
    domain: Mapped[str] = mapped_column(String(255), primary_key=True)
    registrable: Mapped[str] = mapped_column(String(255), index=True)
    tranco_rank: Mapped[int | None] = mapped_column(Integer, nullable=True)
    impersonates: Mapped[str | None] = mapped_column(String(120), nullable=True)
    age_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    registrar: Mapped[str | None] = mapped_column(String(255), nullable=True)
    risk: Mapped[float] = mapped_column(Float, default=0)
    enrichment: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class IP(Base):
    __tablename__ = 'ips'
    ip: Mapped[str] = mapped_column(String(64), primary_key=True)
    asn: Mapped[str | None] = mapped_column(String(32), nullable=True)
    asn_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    country: Mapped[str | None] = mapped_column(String(8), nullable=True)
    abuse_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Detection(Base):
    __tablename__ = 'detections'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email_id: Mapped[str | None] = mapped_column(ForeignKey('emails.id', ondelete='SET NULL'), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(16), default='email')  # email | url | investigation
    target: Mapped[str] = mapped_column(Text, default='')  # subject or URL for display
    risk_score: Mapped[float] = mapped_column(Float, index=True)
    decision: Mapped[str] = mapped_column(String(16), index=True)  # ALLOW | FLAG | QUARANTINE | BLOCK
    scores: Mapped[dict] = mapped_column(JSON, default=dict)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    report: Mapped[dict] = mapped_column(JSON, default=dict)  # full explainable report
    campaign_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    conflicting_intelligence: Mapped[bool] = mapped_column(Boolean, default=False)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    model_versions: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default='open')  # open | confirmed | false_positive | unsure
    demo: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class ThreatIntel(Base):
    __tablename__ = 'threat_intelligence'
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(40), index=True)
    indicator: Mapped[str] = mapped_column(Text)
    ioc_type: Mapped[str] = mapped_column(String(10))
    status: Mapped[str] = mapped_column(String(20))
    verdict: Mapped[str] = mapped_column(String(12))
    risk: Mapped[float] = mapped_column(Float, default=0)
    summary: Mapped[str] = mapped_column(Text, default='')
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class IOC(Base):
    """Local threat feed: OpenPhish / PhishTank / URLhaus ingestion, analyst-confirmed indicators, demo seeds."""
    __tablename__ = 'iocs'
    __table_args__ = (UniqueConstraint('ioc_type', 'value', 'source', name='uq_ioc'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    ioc_type: Mapped[str] = mapped_column(String(10), index=True)  # url | domain | ip | hash
    value: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(40), index=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    demo: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Campaign(Base):
    __tablename__ = 'campaigns'
    id: Mapped[str] = mapped_column(String(40), primary_key=True)  # CAMPAIGN-2026-0001
    name: Mapped[str] = mapped_column(String(200))
    risk: Mapped[float] = mapped_column(Float, default=0)
    brands: Mapped[list] = mapped_column(JSON, default=list)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)  # emails, domains, ips, asns, certs
    centroid: Mapped[list | None] = mapped_column(JSON, nullable=True)  # mean embedding
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    demo: Mapped[bool] = mapped_column(Boolean, default=False)


class Feedback(Base):
    __tablename__ = 'feedback'
    id: Mapped[int] = mapped_column(primary_key=True)
    detection_id: Mapped[str] = mapped_column(ForeignKey('detections.id', ondelete='CASCADE'), index=True)
    label: Mapped[str] = mapped_column(String(20))  # confirmed_phishing | false_positive | unsure
    analyst: Mapped[str] = mapped_column(String(120), default='')
    note: Mapped[str] = mapped_column(Text, default='')
    used_for_training: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ResponseAction(Base):
    __tablename__ = 'response_actions'
    id: Mapped[int] = mapped_column(primary_key=True)
    detection_id: Mapped[str] = mapped_column(ForeignKey('detections.id', ondelete='CASCADE'), index=True)
    action: Mapped[str] = mapped_column(String(20))
    mode: Mapped[str] = mapped_column(String(20))  # simulated | live
    target: Mapped[str] = mapped_column(String(40), default='database')  # database | gmail | msgraph | imap
    result: Mapped[str] = mapped_column(Text, default='')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id: Mapped[int] = mapped_column(primary_key=True)
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(80), index=True)
    target: Mapped[str] = mapped_column(Text, default='')
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    ip: Mapped[str] = mapped_column(String(64), default='')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class ModelVersion(Base):
    __tablename__ = 'model_versions'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(40))
    version: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20))
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    trained_at: Mapped[str] = mapped_column(String(40))


class DriftSnapshot(Base):
    __tablename__ = 'drift_snapshots'
    id: Mapped[int] = mapped_column(primary_key=True)
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
