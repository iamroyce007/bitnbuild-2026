"""End-to-end feature check against a running PhishGraph server (local or deployed).

    python scripts/feature_check.py                         # http://localhost:8000
    python scripts/feature_check.py --base https://phishgraph.vercel.app --no-feedback

Checks every public feature through the HTTP API exactly as the dashboard and the extension use it, and scores
URL verdicts against expectations: real brand domains must be ALLOWed, look-alikes and scam infrastructure must
be at least FLAGged. Writes data/processed/feature_check.json. Exit code 1 if anything failed.
Note: analyses are stored as detections on the target server (that is what the product does).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
RANK = {'ALLOW': 0, 'FLAG': 1, 'QUARANTINE': 2, 'BLOCK': 3}

# (url, expectation): 'allow' = must be ALLOW; 'flag' = FLAG or worse; 'any' = recorded only
URLS: list[tuple[str, str, str]] = [
    # real brands and everyday sites: must not be flagged (the "google vs g00gle" rule, both directions)
    ('https://www.google.com/', 'allow', 'brand'), ('https://accounts.google.com/signin', 'allow', 'brand'),
    ('https://pay.google.com/', 'allow', 'brand'), ('https://opensource.google/', 'allow', 'brand-tld'),
    ('https://github.com/login', 'allow', 'brand'), ('https://www.paypal.com/signin', 'allow', 'brand'),
    ('https://www.microsoft.com/', 'allow', 'brand'), ('https://login.microsoftonline.com/', 'allow', 'brand'),
    ('https://www.apple.com/', 'allow', 'brand'), ('https://www.amazon.in/', 'allow', 'brand'),
    ('https://www.onlinesbi.sbi/', 'allow', 'bank'), ('https://www.hdfcbank.com/', 'allow', 'bank'),
    ('https://www.icicibank.com/', 'allow', 'bank'), ('https://www.netflix.com/in/', 'allow', 'brand'),
    ('https://en.wikipedia.org/wiki/Phishing', 'allow', 'everyday'), ('https://www.irctc.co.in/', 'allow', 'gov-ish'),
    ('https://www.incometax.gov.in/', 'allow', 'gov'), ('https://web.whatsapp.com/', 'allow', 'brand'),
    ('https://www.appleseedfoundation.org/', 'allow', 'common-word'), ('https://www.bbc.co.uk/news', 'allow', 'everyday'),
    # look-alikes: digit swaps, rn/m, homoglyphs, punycode, combos, TLD swaps
    ('https://g00gle.com/login', 'flag', 'digit-swap'), ('https://paypa1.com/signin', 'flag', 'digit-swap'),
    ('https://rnicrosoft.com/account', 'flag', 'rn-m'), ('https://arnazon.in/orders', 'flag', 'rn-m'),
    ('https://xn--ggle-docs-02ha.com/', 'flag', 'punycode'), ('https://gооgle.com/', 'flag', 'cyrillic'),
    ('https://faceb00k-login.top/', 'flag', 'combo'), ('https://apple-id-verify.xyz/', 'flag', 'combo'),
    ('https://microsoft-login-security.xyz/verify', 'flag', 'combo'), ('https://netflix-billing-update.com/pay', 'flag', 'combo'),
    ('https://sbi-kyc-update.site/kyc', 'flag', 'bank-combo'), ('https://hdfc-netbanking-verify.in/login', 'flag', 'bank-combo'),
    ('https://whatsapp-web-verify.online/', 'flag', 'combo'), ('https://paypal.com.secure-login.info/', 'flag', 'subdomain-trick'),
    ('https://www.google.com@evil-login.xyz/', 'flag', 'userinfo-trick'), ('http://192.0.2.10/paypal/login.php', 'flag', 'ip-host'),
    ('https://amaz0n-refund.shop/claim', 'flag', 'digit-combo'), ('https://icici-rewards-points.top/redeem', 'flag', 'bank-combo'),
    ('https://incometax-refund-gov.in/refund', 'flag', 'gov-combo'), ('https://dhl-parcel-track.info/pay', 'flag', 'courier'),
    ('https://hyeonseok067.gitbuh.io/', 'flag', 'permutation'), ('https://gogole.com/accounts', 'flag', 'permutation'),
    ('https://hyeonseok067.github.io/', 'allow', 'brand-pages'),
    # ambiguous or special: recorded, not scored
    ('https://bit.ly/3xYz12a', 'any', 'shortener'), ('https://example.com/', 'any', 'reserved'),
]

MESSAGES = [
    ('email', {'subject': 'Your PayPal account has been limited', 'sender': 'PayPal <service@paypa1-billing.com>',
               'body': 'We noticed unusual activity. Confirm your details within 48 hours at https://paypa1-billing.com/webscr?cmd=login'}, 'flag'),
    ('email', {'subject': 'Your GitHub password was reset', 'sender': 'GitHub <noreply@github.com>',
               'body': 'The password for your GitHub account was recently changed. If you did this, no action is needed. Otherwise visit https://github.com/settings/security'}, 'allow'),
    ('email', {'subject': 'Lunch on Friday?', 'sender': 'Priya <priya.k@gmail.com>', 'body': 'Hey, are we still on for lunch on Friday at 1? Let me know.'}, 'allow'),
    ('sms', {'sender': 'VM-SBIINB', 'body': 'Dear SBI customer, your YONO account will be blocked today due to pending KYC. Update PAN now: sbi-kyc-update.site/kyc . Share OTP with our officer.'}, 'flag'),
    ('sms', {'sender': 'AX-HDFCBK', 'body': 'Rs 2,500.00 debited from a/c **1234 on 28-09-26 to VPA swiggy@icici. Not you? Call 18002586161.'}, 'allow'),
    ('sms', {'sender': '+919876543210', 'body': 'प्रिय ग्राहक, आपका बिजली कनेक्शन आज रात 9:30 बजे काट दिया जाएगा। तुरंत कॉल करें 9876501234'}, 'flag'),
    ('sms', {'sender': '+919003112233', 'body': 'அன்புள்ள நுகர்வோரே, உங்கள் மின் இணைப்பு இன்று இரவு 9.30 மணிக்கு துண்டிக்கப்படும். உடனடியாக அழைக்கவும் 9876501234 அல்லது tneb-bill-pay.in'}, 'flag'),
    ('whatsapp', {'sender': 'Rahul Boss', 'body': "Hi, I'm in a meeting. Need you to buy 4 Amazon gift cards of Rs 5,000 each urgently and send the codes."}, 'flag'),
]

SCREENSHOTS = {
    'iphone-sms': ('9:41\nLTE\n< 12\nAX-HDFCBK >\nText Message • SMS\nToday 9:12 AM\nYour HDFC Bank NetBanking is blocked. Reactivate\nnow at hdfc-netbanking-verify.in/login', {'channel': 'sms', 'sender': 'AX-HDFCBK'}),
    'android-sms': ('VM-SBIINB\nDear SBI customer, update KYC at\nhttps://sbi-kyc-upd\nate.site/kyc within 24 hours. OTP 482913 10:24 AM\nDelivered', {'channel': 'sms', 'sender': 'VM-SBIINB'}),
    'whatsapp': ('Rahul Boss\nonline\nHi, need 4 Amazon gift cards 10:02 pm\nurgently. Call +91 98765 43210 10:03 pm ✓✓', {'channel': 'whatsapp', 'sender': 'Rahul Boss'}),
    'gmail-app': ('Inbox\nAction required: verify your Microsoft 365 account Inbox\nM\nMicrosoft Security 10:24 AM\nto me\nVerify at https://microsoft-login-security.xyz/verify', {'channel': 'email', 'sender': 'Microsoft Security', 'subject': 'Action required: verify your Microsoft 365 account'}),
    'gmail-web': ('Invoice INV-20931 overdue External Inbox\nAccounts Team (billing@invoice-portal.top)\nto me\nPay today via https://invoice-portal.top/pay', {'channel': 'email', 'sender': 'Accounts Team <billing@invoice-portal.top>'}),
    'outlook': ('From: DHL Express <noreply@dhl-parcel-track.info>\nSent: Monday, September 28, 2026 10:24 AM\nTo: Anirudh\nSubject: Your parcel is on hold\nPay the Rs. 49 fee at http://dhl-parcel-track.info/pay', {'channel': 'email', 'subject': 'Your parcel is on hold'}),
}


class Check:
    def __init__(self):
        self.rows: list[dict] = []

    def add(self, area: str, name: str, ok: bool, detail: str = '', ms: float | None = None):
        self.rows.append({'area': area, 'check': name, 'ok': bool(ok), 'detail': detail, 'ms': None if ms is None else round(ms)})
        mark = 'PASS' if ok else 'FAIL'
        print(f'  {mark}  {area:<11} {name:<46} {detail[:70]}{"" if ms is None else f"  ({ms:.0f} ms)"}')


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--base', default=os.getenv('PHISHGRAPH_URL', 'http://localhost:8000'))
    ap.add_argument('--key', default=os.getenv('PHISHGRAPH_KEY', ''))
    ap.add_argument('--no-feedback', action='store_true', help='skip the feedback step (it adds an indicator to the feed)')
    ap.add_argument('--no-record', action='store_true', help='do not append this run to data/validation/history.json')
    a = ap.parse_args()
    base = a.base.rstrip('/')
    headers = {'X-API-Key': a.key} if a.key else ({'X-API-Key': 'dev-local-key'} if 'localhost' in base or '127.0.0.1' in base else {})
    c = httpx.Client(base_url=base, headers=headers, timeout=60, follow_redirects=True)
    ck = Check()

    def call(method: str, path: str, **kw):
        # behave like a polite client: when the server rate-limits (429), wait and retry instead of recording a failure
        for attempt in range(6):
            t = time.perf_counter()
            r = c.request(method, path, **kw)
            if r.status_code != 429:
                return r, (time.perf_counter() - t) * 1000
            time.sleep(float(r.headers.get('retry-after') or 2 + 2 * attempt))
        return r, (time.perf_counter() - t) * 1000

    print(f'PhishGraph feature check against {base}\n')
    # ---- service ---------------------------------------------------------------------------------------------
    r, ms = call('GET', '/health'); ck.add('service', 'GET /health', r.status_code == 200, r.text[:60], ms)
    r, ms = call('GET', '/ready'); ck.add('service', 'GET /ready', r.status_code == 200 and r.json().get('ready') is True, '', ms)
    r, ms = call('GET', '/metrics'); ck.add('service', 'GET /metrics (Prometheus)', r.status_code == 200 and 'phishgraph_' in r.text, '', ms)
    for path in ('/', '/analyze', '/feed', '/system', '/setup', '/graph'):
        r, ms = call('GET', path); ck.add('dashboard', f'GET {path} serves the app', r.status_code == 200 and '<div id="root">' in r.text, '', ms)
    for path in ('/manifest.webmanifest', '/apple-touch-icon.png', '/favicon.svg'):
        r, ms = call('GET', path); ck.add('dashboard', f'GET {path}', r.status_code == 200 and not r.text.startswith('<!doctype'), '', ms)
    r, ms = call('GET', '/downloads/phishgraph-extension.zip')
    ck.add('extension', 'extension zip download', r.status_code == 200 and r.content[:2] == b'PK' and b'manifest.json' in r.content, f'{len(r.content) // 1024} KB', ms)

    # ---- URLs -------------------------------------------------------------------------------------------------
    url_rows = []
    for url, expect, kind in URLS:
        r, ms = call('POST', '/api/v1/analyze/url', json={'url': url})
        if r.status_code != 200:
            ck.add('url', url, expect == 'any', f'HTTP {r.status_code}', ms)
            continue
        j = r.json()
        d, score = j['decision'], j['risk_score']
        ok = expect == 'any' or (expect == 'allow' and d == 'ALLOW') or (expect == 'flag' and RANK[d] >= 1)
        top = (j['reasons'][0]['text'] if j['reasons'] else '')
        ck.add('url', url, ok, f'{d} {score:.0f} [{kind}] {top}', ms)
        url_rows.append({'url': url, 'kind': kind, 'expect': expect, 'decision': d, 'risk': score, 'ok': ok})

    # ---- messages ---------------------------------------------------------------------------------------------
    first_id = None
    for chan, msg, expect in MESSAGES:
        r, ms = call('POST', '/api/v1/analyze/email', json={**msg, 'channel': chan})
        if r.status_code != 200:
            ck.add('message', f'{chan}: {msg["body"][:40]}', False, f'HTTP {r.status_code}', ms)
            continue
        j = r.json()
        first_id = first_id or (j['detection_id'] if RANK[j['decision']] >= 2 else None)
        ok = (expect == 'allow' and j['decision'] == 'ALLOW') or (expect == 'flag' and RANK[j['decision']] >= 1)
        ck.add('message', f'{chan}: {msg["body"][:40]}', ok, f'{j["decision"]} {j["risk_score"]:.0f}', ms)

    # ---- the brand-claim guarantee (brand_guard.py): impersonation with an unofficial link is never ALLOWed ------
    GUARD = [
        ('email', {'subject': 'SBI: your account needs attention', 'sender': 'SBI Alerts <alerts@sbi-notify.help>', 'body': 'Review your account: https://sites.google.com/view/sbi-account-review'}, True),
        ('email', {'subject': 'Netflix: update your payment', 'sender': 'Netflix <billing@nflx-mail.net>', 'body': 'Update payment at https://netflix-billing-help.com/pay'}, True),
        ('sms', {'sender': '+919811112222', 'body': 'HDFC Bank: KYC pending, account will be blocked. Verify at hdfc-kyc-verify.site/login'}, True),
        ('email', {'subject': 'Amazon: order shipped', 'sender': 'Amazon <shipment-tracking@amazon.in>', 'body': 'Track your parcel at https://www.amazon.in/gp/your-account/orders'}, False),
    ]
    for chan, msg, expect_guard in GUARD:
        r, ms = call('POST', '/api/v1/analyze/email', json={**msg, 'channel': chan})
        j = r.json() if r.status_code == 200 else {}
        guarded = bool(j.get('report', {}).get('brand_guard'))
        ok = r.status_code == 200 and ((guarded and j['decision'] != 'ALLOW') if expect_guard else (not guarded))
        ck.add('guarantee', ('impersonation' if expect_guard else 'genuine') + f': {msg["subject"] if "subject" in msg else msg["body"][:40]}', ok,
               f'{j.get("decision")} {j.get("risk_score", 0):.0f} guard={"yes" if guarded else "no"}', ms)

    # ---- screenshot text extraction ---------------------------------------------------------------------------
    for name, (text, want) in SCREENSHOTS.items():
        r, ms = call('POST', '/api/v1/extract', json={'text': text, 'hint': 'auto'})
        j = r.json() if r.status_code == 200 else {}
        ok = r.status_code == 200 and all(j.get(k) == v for k, v in want.items()) and (j['entities']['urls'] or j['entities']['phones'])
        ck.add('screenshot', f'layout: {name}', ok, f'{j.get("channel")} | {j.get("sender")} | {j.get("subject", "")[:30]}', ms)

    # ---- investigation, SSRF --------------------------------------------------------------------------------
    t0 = time.perf_counter()
    r, _ = call('POST', '/api/v1/investigate', json={'url': 'https://paypa1-billing.com/webscr'})
    s: dict = {}
    if r.status_code == 202:
        jid = r.json()['job_id']
        for _ in range(90):
            s = call('GET', f'/api/v1/jobs/{jid}')[0].json()
            if s['status'] in ('done', 'failed'):
                break
            time.sleep(0.5)
    res = s.get('result') or {}
    ok = s.get('status') == 'done' and 'risk_score' in res
    detail = f"{res.get('decision', '')} {res.get('risk_score', '')}" if ok else (s.get('status') or f'HTTP {r.status_code}')
    ck.add('investigate', 'async investigation completes (full chain)', ok, detail, (time.perf_counter() - t0) * 1000)
    for bad in ('http://localhost/admin', 'http://169.254.169.254/latest/meta-data', 'http://10.0.0.5/', 'http://[::1]/'):
        r, ms = call('POST', '/api/v1/investigate', json={'url': bad})
        ck.add('ssrf', f'refuses {bad}', r.status_code in (400, 403, 422), f'HTTP {r.status_code}', ms)

    # ---- data, graph, intel -------------------------------------------------------------------------------
    r, ms = call('GET', '/api/v1/detections?limit=20'); ck.add('data', 'list detections', r.status_code == 200 and isinstance(r.json(), list), f'{len(r.json())} rows', ms)
    if first_id:
        r, ms = call('GET', f'/api/v1/detection/{first_id}'); ck.add('data', 'detection report (explainable)', r.status_code == 200 and bool(r.json().get('report', {}).get('reasons')), f"{len(r.json().get('report', {}).get('reasons', []))} reasons" if r.status_code == 200 else '', ms)
        r, ms = call('GET', f'/api/v1/graph/detection/{first_id}?depth=3'); ck.add('graph', 'detection neighbourhood', r.status_code == 200 and len(r.json().get('nodes', [])) > 0, f'{len(r.json().get("nodes", []))} nodes', ms)
        if not a.no_feedback:
            r, ms = call('POST', '/api/v1/feedback', json={'detection_id': first_id, 'label': 'confirmed_phishing', 'note': 'feature_check'})
            ck.add('feedback', 'confirm phishing -> indicators', r.status_code == 200, json.dumps(r.json())[:60], ms)
    r, ms = call('GET', '/api/v1/graph/domain/paypa1-billing.com'); ck.add('graph', 'domain neighbourhood', r.status_code == 200, f'{len(r.json().get("nodes", []))} nodes', ms)
    r, ms = call('GET', '/api/v1/graph/overview'); ck.add('graph', 'overview graph', r.status_code == 200 and 'nodes' in r.json(), f'{len(r.json().get("nodes", []))} nodes', ms)
    r, ms = call('GET', '/api/v1/domain/g00gle.com'); ck.add('intel', 'domain profile', r.status_code == 200, '', ms)
    r, ms = call('GET', '/api/v1/campaigns'); ck.add('campaigns', 'list campaigns', r.status_code == 200, f'{len(r.json())} campaigns', ms)
    if r.status_code == 200 and r.json():
        cid = r.json()[0]['id']
        r, ms = call('GET', f'/api/v1/campaign/{cid}'); ck.add('campaigns', 'campaign detail', r.status_code == 200, cid, ms)
    r, ms = call('GET', '/api/v1/threat-feed?limit=5'); ck.add('intel', 'threat feed', r.status_code == 200, f'{r.json().get("total", "?")} indicators', ms)
    r, ms = call('GET', '/api/v1/providers'); ck.add('intel', 'providers status', r.status_code == 200, '', ms)
    r, ms = call('GET', '/api/v1/models'); ck.add('models', 'model registry', r.status_code == 200, '', ms)
    r, ms = call('GET', '/api/v1/statistics?hours=24'); ck.add('data', 'statistics', r.status_code == 200 and 'by_decision' in r.json(), '', ms)
    r, ms = call('GET', '/api/v1/sample-data'); ck.add('data', 'sample data status', r.status_code == 200, json.dumps(r.json())[:60], ms)
    r, ms = call('GET', '/api/v1/events/recent'); ck.add('live', 'event stream (polling fallback)', r.status_code == 200, '', ms)
    r, ms = call('GET', '/api/v1/validation'); ck.add('history', 'training & validation history', r.status_code == 200 and 'training' in r.json(),
                                                     f'{len(r.json().get("training", []))} model versions, {len(r.json().get("runs", []))} runs' if r.status_code == 200 else '', ms)
    for path in ('/validation',):
        r, ms = call('GET', path); ck.add('dashboard', f'GET {path} serves the app', r.status_code == 200 and '<div id="root">' in r.text, '', ms)

    # ---- summary ------------------------------------------------------------------------------------------
    failed = [x for x in ck.rows if not x['ok']]
    scored = [x for x in url_rows if x['expect'] != 'any']
    fp = [x['url'] for x in scored if x['expect'] == 'allow' and not x['ok']]
    fn = [x['url'] for x in scored if x['expect'] == 'flag' and not x['ok']]
    summary = {'base': base, 'checks': len(ck.rows), 'passed': len(ck.rows) - len(failed),
               'urls_scored': len(scored), 'false_positives': fp, 'false_negatives': fn,
               'ran_at': time.strftime('%Y-%m-%dT%H:%M:%S')}
    out = ROOT / 'data' / 'processed' / 'feature_check.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({'summary': summary, 'rows': ck.rows, 'urls': url_rows}, indent=1, ensure_ascii=False))
    if not a.no_record:
        sys.path.insert(0, str(ROOT / 'backend'))
        from app.services import validation_log
        validation_log.append('feature_check', summary, {'rows': ck.rows, 'urls': url_rows}, target=base)
    print(f"\n{summary['passed']}/{summary['checks']} checks passed. URLs: {len(scored) - len(fp) - len(fn)}/{len(scored)} as expected "
          f"(false positives {len(fp)}, false negatives {len(fn)}). Saved {out.relative_to(ROOT)}")
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
