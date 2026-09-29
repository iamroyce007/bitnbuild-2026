"""Turn OCR text from a screenshot (SMS / WhatsApp / Gmail / Outlook) into a structured message plus every entity
it contains, so a person can check what was read before it is analysed.

OCR runs in the browser (the image never leaves the device); this module only sees the recognised text. It:
1. repairs typical OCR damage to links (a URL split across lines, spaces around dots, "hxxp", [.], O/0 slips
   inside the scheme) without inventing anything: every repair is listed in `repairs`;
2. strips phone / mail-app chrome (status bar, timestamps, "Reply", "to me", "Delivered" ...);
3. works out the layout: sender, subject (email) and body;
4. extracts links, email addresses, phone numbers, UPI IDs, crypto wallets, amounts, one-time codes, deadlines,
   claimed brands and Indian DLT sender headers (e.g. VM-SBIINB).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .brand_engine import get_brand_engine
from .text_normalizer import deobfuscate
from .url_extractor import RE_EMAIL, TLDS, extract_indicators, extract_urls

# ---- chrome that screenshots carry but messages do not -------------------------------------------------------------
_CHROME = [re.compile(p, re.I) for p in (
    r'^\d{1,2}[:.]\d{2}(\s?[ap]\.?m\.?)?$',                        # 10:24 / 10:24 AM
    r'^(today|yesterday|now|just now)(\s*[,·]?\s*\d{1,2}[:.]\d{2}(\s?[ap]m)?)?$',
    r'^(mon|tue|wed|thu|fri|sat|sun)[a-z]*,?\s.*\d{1,2}[:.]\d{2}.*$',
    r'^\d{1,2}\s(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*(\s\d{2,4})?(,?\s\d{1,2}[:.]\d{2}.*)?$',
    r'^(delivered|read|sent|seen|sending|failed|edited)(\s.*)?$',
    r'^(reply|reply all|forward|archive|delete|mark as unread|more|snooze|move to|report spam|block|block number|unblock)$',
    r'^(text message|imessage|sms|rcs message|chat|messages|inbox|primary|promotions|social|updates|spam)(\s.*)?$',
    r'^(to me|to: me|me)$', r'^to me\b.*$',
    r'^(type a message|text message|message|write a message|start chat|add to contacts|report junk|this sender is not in your contact list.*)$',
    r'^(\d{1,3}%|lte|5g|4g|volte|vo lte|wi-?fi)(\s.*)?$',
    r'^[<>←→‹›\s|·•○●◀▶…x+]{1,4}$',                                 # arrows, bullets, lone icons read as text
    r'^(unsubscribe|view in browser|show original|translate message|see translation)$',
    # iPhone Messages / Android Messages
    r'^(text message|imessage|sms|rcs)\s*[•·-]\s*(sms|imessage|rcs|today|yesterday).*$', r'^[<‹]\s*\d{0,4}$', r'^(details|info|tap to load preview|tap to view|unknown sender|mark as not spam|report spam|delete and report spam|kept|filtered)$',
    r'^(the sender is not in your contact list\.?.*|if you did not expect this message.*)$',
    # WhatsApp
    r'^(online|typing\.*|last seen .*|tap here for contact info|tap for more info|not a contact|add to contacts|safety tools|report|block|add|forwarded|forwarded many times)$',
    r'^.*(end-to-end encrypted|uses a secure service from meta|this business (uses|is)).*$',
    # Gmail / Outlook (app and web)
    r'^(reply all|summari[sz]e this email|show quoted text|external|be careful with this message.*|this message seems dangerous.*|why is this message in spam\??.*|report not spam)$',
    r'^(focused|other|important|starred|all mail|sent:.*|date:.*|cc:.*|bcc:.*|to:.*)$',
    r'^[A-Z]$',                                                       # a sender avatar letter
    r'^\d{1,2}[:.]\d{2}\s?([ap]\.?m\.?)?\s*\(.*ago\)$',              # 10:24 AM (2 hours ago)
    r'^(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s\d{1,2}(,?\s\d{4})?(,?\s\d{1,2}[:.]\d{2}.*)?$',
    r'^(9:41|[•·.]{2,6}|[•·]{1,3}\s*(lte|5g|4g)?)$',
)]
# chat bubble clutter: a trailing time (with optional read ticks) and a leading quote bar
_BUBBLE_TIME = re.compile(r'\s+\d{1,2}[:.]\d{2}\s?(?:[ap]\.?m\.?)?\s*[✓✔√/Vv]{0,2}\s*$', re.I)
_BUBBLE_LEAD = re.compile(r'^[|>¦│]\s+')
_LABEL_CHIP = re.compile(r'(?:\s+(?:inbox|spam|external|important|promotions|updates|social)\s*[x×]?)+$', re.I)  # Gmail label chips
_DLT = re.compile(r'\b([A-Z]{2})-([A-Z0-9]{6})(?:-[A-Z])?\b')          # TRAI DLT header, e.g. VM-SBIINB, JD-HDFCBK-S
_SHORTCODE = re.compile(r'^\s*(?:\+?\d[\d\s-]{4,15}\d|[A-Z]{2}-[A-Z0-9]{6}(?:-[A-Z])?|[A-Z0-9]{5,9})\s*$')
_FROM_LINE = re.compile(r'^(?:from:\s*)?(?P<name>[^<>()«»\[\]@\n]{1,80}?)\s*[<(«\[]\s*(?P<addr>[^<>()«»\[\]\s]+@[^<>()«»\[\]\s]+?)\s*[>)»\]]', re.I)
_FROM_BARE = re.compile(r'^(?:from:\s*)?(?P<name>[^@\n]{2,60}?)\s+(?P<addr>[\w.+-]+@[\w-]+(?:\.[\w-]+)+)\s*$', re.I)
_TO_ME = re.compile(r'^to (me|you)\b', re.I)
RE_URL_LIKE = re.compile(r'https?://|www\.|@')
_SUBJECT = re.compile(r'^subject:\s*(.+)$', re.I)
_AMOUNT = re.compile(r'(?:₹|rs\.?|inr|usd|\$|€|£)\s?\d[\d,]*(?:\.\d{1,2})?|\b\d[\d,]*(?:\.\d{1,2})?\s?(?:rupees|rs\.?|inr|lakh|crore)\b', re.I)
_CODE = re.compile(r'\b(?:otp|code|pin|passcode|verification code|password)\b[^\n\d]{0,20}(\d{4,8})\b|\b(\d{4,8})\b[^\n]{0,20}\b(?:is your|as your)\b[^\n]{0,20}\b(?:otp|code|pin)\b', re.I)
_DEADLINE = re.compile(r'\b(?:within|in|before|by|till|until)\s+(?:the\s+next\s+)?(?:\d{1,3}\s?(?:hours?|hrs?|minutes?|mins?|days?)|today|tonight|midnight|\d{1,2}(?:[:.]\d{2})?\s?(?:am|pm))\b'
                       r'|\b(?:today|tonight)\b[^.\n]{0,30}\b(?:\d{1,2}[:.]\d{2}|\d{1,2}\s?(?:am|pm)|midnight)\b', re.I)


@dataclass
class Extraction:
    channel: str = 'sms'
    sender: str = ''
    subject: str = ''
    body: str = ''
    entities: dict = field(default_factory=dict)
    repairs: list[str] = field(default_factory=list)
    removed_lines: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _repair_links(text: str, repairs: list[str]) -> str:
    """Undo OCR damage to links. Conservative: only touches text that is already link-shaped."""
    out = text
    # scheme slips: "https;//", "https:/ /", "http : //", "hltps://", "htps://"
    fixed = re.sub(r'\b(h[tl]{1,2}ps?|hxxps?)\s*[:;]\s*/\s*/\s*', lambda m: ('https://' if m.group(1).lower().endswith('s') else 'http://'), out, flags=re.I)
    if fixed != out:
        repairs.append('fixed a damaged "http(s)://" prefix')
        out = fixed
    # a link broken at the end of a line: "https://sbi-kyc-upd\nate.site/kyc" or "https://sbi.\nsite/x"
    lines = out.split('\n')
    i, joined = 0, False
    while i < len(lines) - 1:
        tail = lines[i].rstrip().rsplit(' ', 1)[-1]
        nxt = lines[i + 1].lstrip()
        if re.match(r'(?:https?://|www\.)\S+$', tail, re.I) and re.match(r'[\w\-./?=&%#~]', nxt or ' '):
            host = re.sub(r'^(?:https?://)', '', tail, flags=re.I).split('/')[0]
            if '.' not in host.strip('.') or tail[-1] in '-./_=?&':  # the host is unfinished, or it ends mid-separator
                lines[i] = lines[i].rstrip() + nxt
                del lines[i + 1]
                joined = True
                continue
        i += 1
    if joined:
        repairs.append('joined a link that was wrapped onto the next line')
        out = '\n'.join(lines)
    # spaces around dots inside a domain: "sbi-kyc . site" / "paypa1 .com" (only before a real top-level domain)
    tld = rf'(?:{TLDS})'
    spaced = re.sub(rf'\b([a-z0-9-]{{2,}})\s*\.\s+({tld})\b(?=[/\s]|$)', r'\1.\2', out)
    spaced = re.sub(rf'\b([a-z0-9-]{{2,}})\s+\.\s*({tld})\b(?=[/\s]|$)', r'\1.\2', spaced)
    if spaced != out:
        repairs.append('removed spaces the OCR put around dots in a domain')
        out = spaced
    return out


def _is_chrome(line: str) -> bool:
    s = line.strip()
    return not s or any(rx.match(s) for rx in _CHROME)


def _sender_of(line: str) -> str | None:
    """'Name <a@b>' (brackets possibly misread as () « [ ), 'Name a@b', or a bare address -> 'Name <a@b>'."""
    line = re.sub(r'^from:\s*', '', line.strip(), flags=re.I)
    line = _BUBBLE_TIME.sub('', line)                                     # "PayPal Service 10:24 AM"
    for rx in (_FROM_LINE, _FROM_BARE):
        m = rx.match(line)
        if m:
            name = m.group('name').strip(' ,:-')
            return f"{name} <{m.group('addr').strip()}>" if name else m.group('addr').strip()
    m = RE_EMAIL.fullmatch(line.strip('<>() '))
    return m.group(0) if m else None


def _layout(lines: list[str], hint: str, anchors: dict) -> tuple[str, str, str, str]:
    """Return (channel, sender, subject, body) from cleaned lines. `anchors` holds positions of removed chrome that
    carries layout meaning, e.g. Gmail's "to me" line sits right under the sender's name."""
    text = '\n'.join(lines)
    subject = sender = ''
    body_lines = list(lines)
    head = lines[:10]
    email_like = (hint == 'email' or anchors.get('to_me') is not None or bool(re.search(r'(^|\n)(from:|subject:)', text, re.I))
                  or any(_sender_of(l) for l in lines[:6]))
    if hint == 'sms':
        email_like = False

    if email_like:
        for i, l in enumerate(head):
            m = _SUBJECT.match(l)
            if m:
                subject = _LABEL_CHIP.sub('', m.group(1).strip())
                body_lines[i] = ''
        si = None
        for i, l in enumerate(head):
            snd = _sender_of(l)
            if snd:
                sender, si = snd, i
                break
        if si is None and anchors.get('to_me') is not None:
            # Gmail app: "PayPal Service" then "to me"; the address is hidden until the header is expanded
            k = anchors['to_me'] - 1
            if 0 <= k < len(lines) and not RE_URL_LIKE.search(lines[k]):
                sender, si = _BUBBLE_TIME.sub('', lines[k]).strip(), k
        if si is not None:
            body_lines[si] = ''
            if not subject:  # the subject is the first real line above the sender
                above = [(j, x) for j, x in enumerate(lines[:si]) if x.strip() and not re.match(r'^(from|to|cc|date|sent):', x, re.I)]
                if above:
                    j, x = above[0]
                    subject = _LABEL_CHIP.sub('', x.strip())
                    body_lines[j] = ''
        body_lines = [re.sub(r'^(from|to|cc|date|sent):.*$', '', l, flags=re.I) for l in body_lines]
        return 'email', sender, subject, '\n'.join(x for x in body_lines if x.strip()).strip()

    # SMS / chat: tidy bubbles, then the sender id (DLT header, short code, number or contact name) on top
    body_lines = [_BUBBLE_LEAD.sub('', _BUBBLE_TIME.sub('', l)) for l in body_lines]
    for i, l in enumerate(body_lines[:3]):
        st = l.strip().rstrip('>›').strip()
        if _SHORTCODE.match(st) or _DLT.search(st):
            sender = st
            body_lines[i] = ''
            break
    first = body_lines[0].strip().rstrip('>›').strip() if body_lines else ''
    # a saved-contact or business name: short, no sentence punctuation, no link, not a greeting
    if (not sender and len(body_lines) > 1 and 1 <= len(first.split()) <= 3 and not re.search(r'[.!?:,/@]|\d{5}', first)
            and not re.match(r'(hi|hello|dear|hey|namaste)\b', first, re.I)):
        sender = first
        body_lines[0] = ''
    channel = 'whatsapp' if anchors.get('whatsapp') or re.search(r'whatsapp|wa\.me/', text, re.I) else 'sms'
    return channel, sender, '', '\n'.join(x for x in body_lines if x.strip()).strip()


def _reflow(body: str) -> str:
    """OCR breaks paragraphs at every visual line: a line that does not end a sentence continues on the next one."""
    out: list[str] = []
    for line in body.split('\n'):
        s = line.strip()
        if out and s and not re.search(r'[.!?:]["\')]?$', out[-1]):
            out[-1] += ' ' + s
        else:
            out.append(s)
    return '\n'.join(out)


def extract_from_ocr(text: str, hint: str = 'auto', ocr_confidence: float | None = None, fields: dict | None = None) -> Extraction:
    """`fields` = {channel, sender, subject, body} already reviewed by a person: skip clean-up and layout guessing
    and only (re)extract the entities, so edits in the review form are respected exactly."""
    ex = Extraction()
    if fields is not None:
        ex.channel, ex.sender, ex.subject, ex.body = fields.get('channel') or 'sms', fields.get('sender', ''), fields.get('subject', ''), fields.get('body', '')
        return _entities(ex, ocr_confidence)
    text = (text or '').replace('\r', '')
    text = re.sub(r'[ \t]+', ' ', text)
    text = _repair_links(text, ex.repairs)

    kept: list[str] = []
    anchors: dict = {}
    for line in text.split('\n'):
        st = line.strip()
        if _TO_ME.match(st):
            anchors.setdefault('to_me', len(kept))  # index of the next kept line; the sender is just before it
        if re.search(r'end-to-end encrypted|last seen|^online$|typing', st, re.I):
            anchors['whatsapp'] = True
        if _is_chrome(line):
            if st:
                ex.removed_lines.append(st)
        else:
            kept.append(st)

    ex.channel, ex.sender, ex.subject, body = _layout(kept, hint, anchors)
    ex.body = _reflow(body)
    return _entities(ex, ocr_confidence)


def _entities(ex: Extraction, ocr_confidence: float | None) -> Extraction:
    norm = deobfuscate(f'{ex.subject}\n{ex.body}')
    full = f'{ex.sender}\n{norm.text}'
    ind = extract_indicators(full)
    urls = []
    for u in extract_urls(norm.text):
        p = u.url
        urls.append({'url': p.normalized, 'host': p.host, 'registrable': p.registrable})
    if ex.sender:
        for m in RE_EMAIL.finditer(ex.sender):
            if m.group(0).lower() not in ind['emails']:
                ind['emails'].insert(0, m.group(0).lower())
    codes = sorted({(m.group(1) or m.group(2)) for m in _CODE.finditer(full)})
    dlt = _DLT.search(ex.sender or '')
    ex.entities = {
        'urls': urls,
        'emails': ind['emails'],
        'phones': ind['phones'],
        'upi_ids': ind['upi_ids'],
        'crypto_wallets': ind['crypto_wallets'],
        'amounts': sorted({re.sub(r'\s+', ' ', a.strip()) for a in _AMOUNT.findall(full)})[:10],
        'codes': codes[:5],
        'deadlines': sorted({m.group(0).strip() for m in _DEADLINE.finditer(full)})[:5],
        'brands_claimed': sorted({b.name.split(' /')[0] for b in get_brand_engine().claimed_brands(full)})[:8],
        'sender_header': ({'header': dlt.group(0), 'route': dlt.group(1), 'entity': dlt.group(2)} if dlt else None),
        'obfuscation': [t['label'] for t in norm.tricks],
    }

    if not ex.body:
        ex.warnings.append('No message text was found. Try a sharper or larger screenshot.')
    if ocr_confidence is not None and ocr_confidence < 70:
        ex.warnings.append(f'Text recognition confidence was low ({ocr_confidence:.0f}%). Check the fields before analysing.')
    if re.search(r'(https?://|www\.)\S*\s*$', ex.body.split('\n')[-1] if ex.body else '') and ex.body.rstrip().endswith(('-', '/', '.')):
        ex.warnings.append('A link at the end may be cut off in the screenshot.')
    if not urls and re.search(r'\b(click|tap|visit|open|link|update|verify)\b', full, re.I):
        ex.warnings.append('The message asks you to click or visit something, but no link could be read. If the screenshot shows one, type it into the body.')
    return ex
