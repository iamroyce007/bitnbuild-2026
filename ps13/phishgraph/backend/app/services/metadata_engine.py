"""Sender / header / attachment analysis. Every signal cites the header value it came from."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..utils.unicode_utils import skeleton
from .brand_engine import get_brand_engine

FREE_MAIL = {'gmail.com', 'yahoo.com', 'yahoo.co.in', 'outlook.com', 'hotmail.com', 'live.com', 'aol.com', 'icloud.com', 'proton.me', 'protonmail.com',
             'rediffmail.com', 'zoho.com', 'yandex.com', 'mail.ru', 'gmx.com', 'gmx.net', 'mail.com', 'tutanota.com'}
# SMS sender IDs in India follow the DLT format "XX-BRANDX"; banks never message from a personal 10-digit number
DLT_HEADER = re.compile(r'^[A-Z]{2}-[A-Z0-9]{3,8}(?:-[A-Z])?$')


@dataclass
class MetaResult:
    score: float  # 0-100
    signals: list[dict] = field(default_factory=list)  # {id, label, weight, evidence}
    claimed_brands: list[str] = field(default_factory=list)
    sender_verdict: dict | None = None
    trust: list[str] = field(default_factory=list)  # verified-sender evidence that lowers risk


def analyze(pm) -> MetaResult:
    be = get_brand_engine()
    sig: list[dict] = []
    trust: list[str] = []

    def add(i: str, label: str, w: float, ev: str = '') -> None:
        sig.append({'id': i, 'label': label, 'weight': w, 'evidence': ev[:200]})

    claimed = be.claimed_brands(f'{pm.sender_name} {pm.subject} {pm.text[:3000]}')
    claimed_names = [b.name for b in claimed]
    sender_v = None
    if pm.sender_domain:
        sender_v = be.analyze(pm.sender_domain)
        if sender_v.findings:
            f = sender_v.findings[0]
            add('sender_lookalike', f'Sender domain {f.evidence}', f.confidence, pm.sender)
        official = sender_v.official_brand
        # display-name deception: "PayPal Security" <alerts@random.xyz>
        for b in claimed:
            name_hit = pm.sender_name and re.search(rf'(?<![a-z]){re.escape(skeleton(b.name.split(" /")[0]))}(?![a-z])', skeleton(pm.sender_name))
            if name_hit and official != b.name and not be.official_brand(pm.sender_domain):
                add('display_name_spoof', f'Display name claims "{pm.sender_name}" but the address is {pm.sender}', 0.55, pm.sender)
                break
        if pm.sender_domain in FREE_MAIL and claimed and any(b.category.startswith(('bank', 'gov', 'payments')) for b in claimed):
            add('freemail_institution', f'Claims to be {claimed[0].name} but sends from a free {pm.sender_domain} mailbox', 0.45, pm.sender)
        if claimed and not official and not sender_v.findings and not any(be.official_brand(pm.sender_domain) == b for b in claimed):
            add('brand_sender_mismatch', f'Mentions {", ".join(claimed_names[:2])} but is sent from unrelated domain {pm.sender_domain}', 0.15, pm.sender)
    if pm.reply_to and pm.sender_domain and '@' in pm.reply_to:
        rd = pm.reply_to.rsplit('@', 1)[1]
        from ..utils.url_utils import registrable
        if registrable(rd) != registrable(pm.sender_domain):
            add('reply_to_mismatch', f'Replies go to {pm.reply_to}, not the sender\'s domain {pm.sender_domain}', 0.3, pm.reply_to)
    if pm.return_path and pm.sender_domain and '@' in pm.return_path:
        from ..utils.url_utils import registrable
        rp = pm.return_path.rsplit('@', 1)[1]
        if registrable(rp) != registrable(pm.sender_domain) and not rp.endswith(('amazonses.com', 'sendgrid.net', 'mailgun.org', 'mcsv.net', 'bounces.google.com', 'salesforce.com', 'mktomail.com', 'sparkpostmail.com')):
            add('return_path_mismatch', f'Return-Path domain {rp} differs from From domain {pm.sender_domain}', 0.1, pm.return_path)
    for mech, w in (('dmarc', 0.4), ('spf', 0.22), ('dkim', 0.2)):
        v = pm.auth.get(mech)
        if v in ('fail', 'softfail', 'permerror'):
            add(f'{mech}_fail', f'{mech.upper()} check: {v}', w if v != 'softfail' else w / 2, f'{mech}={v}')
    for a in pm.attachments:
        if a.double_extension:
            add('double_extension', f'Attachment "{a.filename}" hides its real type behind a double extension', 0.5, a.sha256[:16])
        elif a.extension in ('html', 'htm', 'shtml', 'svg'):
            add('html_attachment', f'HTML/SVG attachment "{a.filename}" (common credential-form trick)', 0.4, a.sha256[:16])
        elif a.risky:
            add('risky_attachment', f'Risky attachment type ".{a.extension}" ({a.filename})', 0.35, a.sha256[:16])
    if pm.channel == 'sms' and pm.sender:
        if re.fullmatch(r'\+?\d{10,13}', pm.sender.replace(' ', '')) and claimed and any(b.category.startswith(('bank', 'gov', 'payments', 'telecom')) for b in claimed):
            add('sms_personal_number', f'Claims to be {claimed[0].name} but comes from a personal mobile number {pm.sender}', 0.45, pm.sender)
        elif DLT_HEADER.match(pm.sender.upper()) and claimed:
            hdr = pm.sender.upper().split('-')[1]
            if any(k.upper()[:3] in hdr for b in claimed for k in (b.keywords or [b.id]) if len(k) >= 3):
                trust.append(f'registered SMS sender header {pm.sender} matches the brand it mentions')
    if pm.html_text_ratio > 40:
        add('html_heavy', f'Message is almost all markup (HTML/text ratio {pm.html_text_ratio})', 0.06, '')
    for t in pm.tricks:
        add(f'evasion_{t["id"]}', t['label'], 0.35 if t['id'] not in ('meta_refresh',) else 0.15, t.get('evidence', ''))

    if pm.sender_domain and pm.sender_domain not in FREE_MAIL and sender_v and sender_v.official_brand and not any(pm.auth.get(m) in ('fail', 'softfail', 'permerror') for m in ('spf', 'dkim', 'dmarc')):
        passed = [m for m in ('dmarc', 'spf', 'dkim') if pm.auth.get(m) == 'pass']
        trust.append(f'sent from {sender_v.official_brand}\'s official domain {pm.sender_domain}' + (f' ({", ".join(passed)} pass)' if passed else ' (no authentication results supplied)'))
    acc = 1.0
    for s in sig:
        acc *= 1 - s['weight']
    return MetaResult(score=round(100 * (1 - acc), 1), signals=sorted(sig, key=lambda s: -s['weight']), claimed_brands=claimed_names,
                      trust=trust, sender_verdict={'domain': pm.sender_domain, 'official_brand': sender_v.official_brand, 'tranco_rank': sender_v.tranco_rank} if sender_v else None)
