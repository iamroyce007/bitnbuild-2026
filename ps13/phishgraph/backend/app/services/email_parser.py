"""Ingestion gateway: raw RFC 822 / .eml / JSON -> a normalised message. Attachments are hashed, never executed."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr

from .text_normalizer import deobfuscate, html_to_text
from .url_extractor import ExtractedURL, extract_indicators, extract_urls

RISKY_EXT = {'exe', 'scr', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'hta', 'bat', 'cmd', 'ps1', 'msi', 'lnk', 'iso', 'img', 'vhd', 'apk', 'jar', 'html', 'htm', 'shtml', 'svg', 'one', 'xll', 'docm', 'xlsm', 'pptm', 'dotm', 'chm', 'reg', 'cpl'}
ARCHIVE_EXT = {'zip', 'rar', '7z', 'gz', 'tar', 'cab', 'ace'}


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    extension: str
    risky: bool
    double_extension: bool


@dataclass
class ParsedMessage:
    channel: str = 'email'  # email | sms | whatsapp | url | other
    message_id: str = ''
    sender: str = ''
    sender_name: str = ''
    sender_domain: str = ''
    recipients: list[str] = field(default_factory=list)
    subject: str = ''
    text: str = ''  # visible, de-obfuscated text used for NLP
    raw_text: str = ''
    html: str = ''
    reply_to: str = ''
    return_path: str = ''
    auth: dict = field(default_factory=dict)  # spf/dkim/dmarc -> pass|fail|softfail|none|...
    received_hops: int = 0
    date: str = ''
    headers: dict = field(default_factory=dict)
    urls: list[ExtractedURL] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    indicators: dict = field(default_factory=dict)
    tricks: list[dict] = field(default_factory=list)
    html_text_ratio: float = 0.0


def _domain(addr: str) -> str:
    return addr.rsplit('@', 1)[-1].lower().strip('>') if '@' in addr else ''


def _auth_results(msg: EmailMessage) -> dict:
    out: dict[str, str] = {}
    for h in (msg.get_all('Authentication-Results') or []) + (msg.get_all('ARC-Authentication-Results') or []):
        for mech in ('spf', 'dkim', 'dmarc'):
            m = re.search(rf'\b{mech}\s*=\s*([a-z]+)', str(h), re.I)
            if m and mech not in out:
                out[mech] = m.group(1).lower()
    rs = msg.get('Received-SPF')
    if rs and 'spf' not in out:
        out['spf'] = str(rs).split()[0].lower()
    return out


def _finish(pm: ParsedMessage, text: str, html: str) -> ParsedMessage:
    tricks: list[dict] = []
    anchors, forms = [], []
    visible = text
    if html:
        n = html_to_text(html)
        tricks += n.tricks
        anchors, forms = n.anchors, n.forms
        visible = n.text if len(n.text) > len(text) * 0.5 else (text or n.text)
        pm.html_text_ratio = round(len(html) / max(1, len(n.text)), 2)
    d = deobfuscate(f'{pm.subject}\n{visible}' if pm.subject else visible)
    tricks += d.tricks
    pm.raw_text = visible
    pm.text = d.text
    pm.html = html
    pm.tricks = tricks
    pm.urls = extract_urls(d.text, anchors, forms)
    pm.indicators = extract_indicators(d.text)
    return pm


def parse_raw_email(raw: bytes | str) -> ParsedMessage:
    if isinstance(raw, str):
        raw = raw.encode('utf-8', 'replace')
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    name, addr = parseaddr(str(msg.get('From', '')))
    pm = ParsedMessage(
        channel='email', message_id=str(msg.get('Message-ID', '')).strip('<>'), sender=addr.lower(), sender_name=name,
        sender_domain=_domain(addr), subject=str(msg.get('Subject', '')), date=str(msg.get('Date', '')),
        recipients=[a for _, a in getaddresses([str(v) for v in (msg.get_all('To') or []) + (msg.get_all('Cc') or [])])][:50],
        reply_to=parseaddr(str(msg.get('Reply-To', '')))[1].lower(), return_path=parseaddr(str(msg.get('Return-Path', '')))[1].lower(),
        auth=_auth_results(msg), received_hops=len(msg.get_all('Received') or []),
        headers={k: str(v)[:500] for k, v in list(msg.items())[:60]},
    )
    text_parts, html_parts = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disp = part.get_content_disposition()
        fn = part.get_filename()
        ctype = part.get_content_type()
        if fn or disp == 'attachment':
            payload = part.get_payload(decode=True) or b''
            fn = fn or 'unnamed'
            exts = fn.lower().split('.')[1:]
            ext = exts[-1] if exts else ''
            pm.attachments.append(Attachment(fn, ctype, len(payload), hashlib.sha256(payload).hexdigest(), ext,
                                             ext in RISKY_EXT or ext in ARCHIVE_EXT, len(exts) >= 2 and exts[-2] in {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'png', 'txt', 'invoice'}))
            continue
        try:
            content = part.get_content()
        except Exception:
            content = (part.get_payload(decode=True) or b'').decode('utf-8', 'replace')
        if ctype == 'text/html':
            html_parts.append(content)
        elif ctype.startswith('text/'):
            text_parts.append(content)
    return _finish(pm, '\n'.join(text_parts), '\n'.join(html_parts))


def parse_json_message(subject: str = '', sender: str = '', body: str = '', html: str = '', channel: str = 'email',
                       reply_to: str = '', headers: dict | None = None, sender_name: str = '') -> ParsedMessage:
    name, addr = parseaddr(sender) if '@' in sender else (sender_name, '')
    pm = ParsedMessage(channel=channel, sender=(addr or sender).lower(), sender_name=sender_name or name, sender_domain=_domain(addr),
                       subject=subject, reply_to=reply_to.lower(), headers=headers or {})
    if headers:
        for mech in ('spf', 'dkim', 'dmarc'):
            m = re.search(rf'\b{mech}\s*=\s*([a-z]+)', str(headers.get('Authentication-Results', '')), re.I)
            if m:
                pm.auth[mech] = m.group(1).lower()
    return _finish(pm, body, html)
