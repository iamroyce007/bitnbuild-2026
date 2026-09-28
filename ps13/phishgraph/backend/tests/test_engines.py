"""Email parsing, evasion handling, URL features/engine, NLP intents, risk fusion, graph engine, threat-intel connectors."""
import asyncio
from email.message import EmailMessage

import httpx
import pytest

from app.connectors import base as ti_base
from app.connectors.providers import URLScan, VirusTotal
from app.services import graph_engine
from app.services.email_parser import parse_json_message, parse_raw_email
from app.services.graph_store import get_graph_store
from app.services.nlp_engine import get_nlp_engine
from app.services.risk_engine import fuse
from app.services.text_normalizer import deobfuscate, html_to_text
from app.services.url_engine import get_url_engine
from app.services.url_features import FEATURE_NAMES, url_features


# ---------- ingestion & evasion ----------
def test_raw_email_parsing_headers_auth_attachments():
    m = EmailMessage()
    m['From'] = 'PayPal Service <service@paypa1-billing.com>'
    m['To'] = 'victim@example.org'
    m['Reply-To'] = 'collect@other-domain.ru'
    m['Subject'] = 'Account limited'
    m['Authentication-Results'] = 'mx.example.org; spf=fail smtp.mailfrom=paypa1-billing.com; dkim=none; dmarc=fail'
    m.set_content('Confirm at https://paypa1-billing.com/webscr?cmd=login')
    m.add_attachment(b'<html>x</html>', maintype='text', subtype='html', filename='invoice.pdf.html')
    pm = parse_raw_email(m.as_bytes())
    assert pm.sender == 'service@paypa1-billing.com' and pm.sender_name == 'PayPal Service'
    assert pm.auth == {'spf': 'fail', 'dkim': 'none', 'dmarc': 'fail'}
    assert pm.reply_to == 'collect@other-domain.ru'
    assert pm.attachments[0].double_extension and pm.attachments[0].sha256
    assert any(u.url.host == 'paypa1-billing.com' for u in pm.urls)


def test_evasion_tricks_are_undone_and_reported():
    d = deobfuscate('Please v​e​rify at hxxps://evil-login[.]xyz/login and log into your pаypal account')
    ids = {t['id'] for t in d.tricks}
    assert {'zero_width', 'defanged_link', 'mixed_script'} <= ids
    assert 'https://evil-login.xyz/login' in d.text and 'paypal' in d.text


def test_html_hidden_text_and_deceptive_link_text():
    n = html_to_text('<p>Hi</p><div style="display:none">cricket weather</div><a href="https://evil.xyz/a">https://paypal.com/login</a>')
    assert any(t['id'] == 'hidden_html_text' for t in n.tricks)
    pm = parse_json_message(subject='s', sender='a@b.com', html='<a href="https://evil.xyz/a">https://paypal.com/login</a>')
    assert any(u.deceptive_text for u in pm.urls)


def test_indicators_extracted():
    pm = parse_json_message(channel='sms', sender='+919876543210', body='Pay to fraud.help@ybl now or call 9123456780')
    assert 'fraud.help@ybl' in pm.indicators['upi_ids'] and '9123456780' in pm.indicators['phones']


# ---------- URL engine ----------
def test_url_features_complete():
    f = url_features('http://198.51.100.7:8080/login.php?redirect=x')
    assert set(FEATURE_NAMES) <= set(f) and f['is_ip'] == 1 and f['has_port'] == 1 and f['n_susp_params'] == 1


@pytest.mark.parametrize('url,lo,hi', [
    ('https://www.google.com/search?q=weather', 0, 10), ('https://accounts.google.com/signin/v2/identifier', 0, 15),
    ('https://g00gle.com/login', 80, 100), ('http://paypal.com.secure-verify.xyz/webscr?cmd=login', 85, 100),
])
def test_url_engine_scores(url, lo, hi):
    r = get_url_engine().analyze(url)
    assert lo <= r.score <= hi, (url, r.score, r.rules)


# ---------- NLP ----------
def test_nlp_intents_multilingual_with_evidence():
    r = get_nlp_engine().analyze('Dear customer your KYC is expired. Share OTP to our officer or account will be blocked today.')
    ids = {i.id for i in r.intents}
    assert {'identity_verification', 'otp_request', 'fear'} <= ids
    assert all(i.evidence for i in r.intents if i.source == 'lexicon')
    t = get_nlp_engine().analyze('உங்கள் மின் இணைப்பு இன்று துண்டிக்கப்படும். உடனடியாக அழைக்கவும்')
    assert {'utility_disconnection', 'urgency'} & {i.id for i in t.intents}


def test_nlp_benign_is_low():
    r = get_nlp_engine().analyze('Hi team, lunch is at 1pm on Friday at the canteen. See you there.')
    assert r.score < 30 and not r.intents


# ---------- fusion ----------
def test_missing_sources_are_renormalised_not_zero():
    f = fuse(nlp=90, url=90, ti=None, graph=None, brand=None, meta=None, families=2)
    assert f.final >= 85 and 'threat_intelligence' in f.unavailable


def test_single_model_score_cannot_quarantine():
    f = fuse(nlp=95, url=None, ti=None, graph=None, brand=None, meta=0, families=0)
    assert f.decision in ('ALLOW', 'FLAG') and f.final <= 40


def test_hard_evidence_floors():
    assert fuse(nlp=10, url=20, ti=95, graph=None, brand=None, meta=None, hard_known_bad=True).final >= 92
    assert fuse(nlp=70, url=60, ti=None, graph=None, brand=90, meta=None, strong_brand=True, families=2).decision == 'BLOCK'


def test_conflicting_intelligence_flagged():
    f = fuse(nlp=60, url=60, ti=5, graph=80, brand=0, meta=0, ti_clean_votes=3, families=3)
    assert f.conflicting_intelligence


# ---------- graph ----------
def test_graph_links_unknown_domain_to_known_bad_via_specific_infrastructure():
    gs = get_graph_store()
    gs.upsert_node('domain:bad-known.xyz', 'domain', {'malicious': True, 'risk': 95})
    gs.upsert_node('ip:203.0.113.9', 'ip', {'asn': 'AS64500'})
    gs.upsert_edge('domain:bad-known.xyz', 'ip:203.0.113.9', 'RESOLVES_TO')
    gs.upsert_node('domain:new-unknown.xyz', 'domain', {'risk': 10})
    gs.upsert_edge('domain:new-unknown.xyz', 'ip:203.0.113.9', 'RESOLVES_TO')
    r = graph_engine.score(['domain:new-unknown.xyz'])
    assert r.components['infrastructure_overlap'] > 0 and any('bad-known.xyz' in p['text'] for p in r.paths)


def test_graph_ignores_shared_cdn_infrastructure():
    gs = get_graph_store()
    gs.upsert_node('domain:evil-on-cdn.xyz', 'domain', {'malicious': True, 'risk': 95})
    gs.upsert_node('ip:104.16.1.1', 'ip', {'asn': 'AS13335'})  # Cloudflare: shared by millions
    gs.upsert_edge('domain:evil-on-cdn.xyz', 'ip:104.16.1.1', 'RESOLVES_TO')
    gs.upsert_node('domain:innocent-blog.com', 'domain', {'risk': 0})
    gs.upsert_edge('domain:innocent-blog.com', 'ip:104.16.1.1', 'RESOLVES_TO')
    r = graph_engine.score(['domain:innocent-blog.com'])
    assert r.score < 15 and not any(p['kind'] == 'shared_infrastructure' for p in r.paths)


# ---------- threat-intel connectors (mocked; no network, no keys) ----------
def _mock(handler):
    orig = ti_base.Connector.client

    def client(**kw):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), headers=kw.get('headers'))
    return orig, client


def test_connector_not_configured_is_explicit():
    r = asyncio.run(VirusTotal().lookup('domain', 'example.com'))
    assert r.status == 'not_configured'


def test_virustotal_mapping_with_mock(monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), 'virustotal_api_key', 'k')
    monkeypatch.setattr(get_settings(), 'enable_external_ti', True)

    def handler(req):
        return httpx.Response(200, json={'data': {'attributes': {'last_analysis_stats': {'malicious': 7, 'suspicious': 1, 'harmless': 60, 'undetected': 20},
                                                                 'last_dns_records': [{'type': 'A', 'value': '203.0.113.5'}]}}})
    _, client = _mock(handler)
    monkeypatch.setattr(ti_base.Connector, 'client', staticmethod(client))
    r = asyncio.run(VirusTotal().lookup('domain', 'bad-mocked.xyz'))
    assert r.status == 'ok' and r.verdict == 'malicious' and r.relations[0]['value'] == '203.0.113.5'


def test_connector_failure_is_reported_not_raised(monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), 'urlscan_api_key', 'k')
    monkeypatch.setattr(get_settings(), 'enable_external_ti', True)
    _, client = _mock(lambda req: httpx.Response(503))
    monkeypatch.setattr(ti_base.Connector, 'client', staticmethod(client))
    r = asyncio.run(URLScan().lookup('domain', 'unavailable-mock.xyz'))
    assert r.status == 'unavailable'


def test_private_indicators_never_sent(monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), 'virustotal_api_key', 'k')
    monkeypatch.setattr(get_settings(), 'enable_external_ti', True)
    assert asyncio.run(VirusTotal().lookup('domain', '10.1.2.3')).status == 'skipped_private'
    assert ti_base.safe_indicator('url', 'https://evil.xyz/reset?email=alice@corp.com') == ('domain', 'evil.xyz')
