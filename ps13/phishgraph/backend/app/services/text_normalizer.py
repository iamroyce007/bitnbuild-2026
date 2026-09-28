"""Undo filter-evasion tricks before any analysis. Each trick found is kept as evidence:
using evasion at all is a strong signal of malicious intent."""
from __future__ import annotations

import html as htmllib
import re
from dataclasses import dataclass, field

from ..utils.unicode_utils import ZERO_WIDTH, script_of, skeleton


@dataclass
class Normalized:
    text: str
    tricks: list[dict] = field(default_factory=list)
    anchors: list[dict] = field(default_factory=list)  # {href, text}
    forms: list[str] = field(default_factory=list)  # form action URLs
    hidden_text: str = ''


_HIDDEN_STYLE = re.compile(
    r'<(?P<tag>[a-z0-9]+)\b[^>]*style\s*=\s*["\'][^"\']*?(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em)?\s*(?:;|["\'])|'
    r'opacity\s*:\s*0(?:\.0+)?\s*(?:;|["\'])|max-height\s*:\s*0|color\s*:\s*(?:#fff(?:fff)?|white|transparent)\s*;[^"\']*font-size\s*:\s*[01]px)[^"\']*["\'][^>]*>(?P<body>.*?)</(?P=tag)>',
    re.I | re.S)


def html_to_text(raw_html: str) -> Normalized:
    tricks: list[dict] = []
    h = re.sub(r'<(script|style|head|title)\b.*?</\1>', ' ', raw_html, flags=re.I | re.S)
    hidden = []

    def _hide(m: re.Match) -> str:
        hidden.append(re.sub(r'<[^>]+>', ' ', m.group('body')))
        return ' '
    h = _HIDDEN_STYLE.sub(_hide, h)
    hidden_text = ' '.join(' '.join(hidden).split())
    if hidden_text:
        tricks.append({'id': 'hidden_html_text', 'label': f'{len(hidden)} block(s) of invisible text inserted to confuse content filters', 'evidence': hidden_text[:160]})
    anchors = []
    for m in re.finditer(r'<a\b[^>]*?href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>', h, re.I | re.S):
        anchors.append({'href': htmllib.unescape(m.group(1).strip()), 'text': ' '.join(htmllib.unescape(re.sub(r'<[^>]+>', ' ', m.group(2))).split())})
    for m in re.finditer(r'<(?:button|input|div|span|td)\b[^>]*?(?:onclick|data-href|data-url)\s*=\s*["\'][^"\']*?(https?://[^"\'\s;)]+)', h, re.I):
        anchors.append({'href': htmllib.unescape(m.group(1)), 'text': '[button]'})
    for m in re.finditer(r'<meta[^>]+http-equiv\s*=\s*["\']?refresh[^>]+url\s*=\s*([^"\'>\s]+)', h, re.I):
        anchors.append({'href': htmllib.unescape(m.group(1)), 'text': '[auto-redirect]'})
        tricks.append({'id': 'meta_refresh', 'label': 'Page auto-redirects with a meta refresh', 'evidence': m.group(1)[:120]})
    forms = [htmllib.unescape(m.group(1)) for m in re.finditer(r'<form\b[^>]*action\s*=\s*["\']([^"\']+)["\']', h, re.I)]
    if re.search(r'<input[^>]+type\s*=\s*["\']?password', h, re.I):
        tricks.append({'id': 'embedded_password_form', 'label': 'Email itself contains a password field (credential form inside the message)', 'evidence': '<input type=password>'})
    text = re.sub(r'<br\s*/?>|</(?:p|div|tr|li|h\d|table)>', '\n', h, flags=re.I)
    text = htmllib.unescape(re.sub(r'<[^>]+>', ' ', text))
    text = re.sub(r'[ \t ]+', ' ', text)
    text = re.sub(r'\n\s*\n+', '\n', text).strip()
    return Normalized(text=text, tricks=tricks, anchors=anchors, forms=forms, hidden_text=hidden_text)


_DEFANG = [
    (re.compile(r'\bh(?:xx|\*\*|tt|XX)p(s?)(?:\[:\]|\(:\)|:)', re.I), r'http\1:'),
    (re.compile(r'\s?\[\s?(?:\.|dot)\s?\]\s?|\s?\(\s?(?:\.|dot)\s?\)\s?|\s?\{\s?(?:\.|dot)\s?\}\s?', re.I), '.'),
    (re.compile(r'\[:\]|\(:\)'), ':'),
    (re.compile(r'\[/\]'), '/'),
]
_SPACED = re.compile(r'\b(?:[A-Za-z][ .\-_*]){3,}[A-Za-z]\b')
_B64 = re.compile(r'(?<![A-Za-z0-9+/=])(?:aHR0c|SFRUU)[A-Za-z0-9+/=_-]{12,}')  # base64 of "http" / "HTTP"


def deobfuscate(text: str) -> Normalized:
    import base64
    tricks: list[dict] = []
    zw = [c for c in text if c in ZERO_WIDTH]
    if zw:
        text = ''.join(c for c in text if c not in ZERO_WIDTH)
        tricks.append({'id': 'zero_width', 'label': f'{len(zw)} invisible zero-width character(s) hidden inside words', 'evidence': ' '.join(f'U+{ord(c):04X}' for c in sorted(set(zw)))})

    mixed = []

    def _fix_word(m: re.Match) -> str:
        w = m.group(0)
        scripts = {script_of(c) for c in w if c.isalpha()}
        if 'LATIN' in scripts and len(scripts - {'LATIN'}) >= 1 and scripts <= {'LATIN', 'CYRILLIC', 'GREEK', 'COMPAT', 'ARMENIAN', 'CHEROKEE'}:
            fixed = skeleton(w)
            mixed.append(f'{w} → {fixed}')
            return fixed
        return w
    text = re.sub(r'\S+', _fix_word, text)
    if mixed:
        tricks.append({'id': 'mixed_script', 'label': 'Words mix alphabets (e.g. Cyrillic letters inside English words) to dodge filters', 'evidence': '; '.join(mixed[:4])})

    before = text
    for rx, rep in _DEFANG:
        text = rx.sub(rep, text)
    if text != before:
        tricks.append({'id': 'defanged_link', 'label': 'Link written in disguised form (hxxp, [.], (dot)) so filters do not recognise it', 'evidence': before[:0] or 'hxxp / [.] notation'})

    spaced = []

    def _join(m: re.Match) -> str:
        w = re.sub(r'[ .\-_*]', '', m.group(0))
        spaced.append(w)
        return w
    # only collapse when it forms a word of 4+ letters, never inside normal sentences of single letters like "a b c"
    text2 = _SPACED.sub(_join, text)
    if spaced and any(len(w) >= 5 for w in spaced):
        text = text2
        tricks.append({'id': 'spaced_letters', 'label': 'Words broken into separate letters to evade keyword filters', 'evidence': ', '.join(spaced[:4])})

    for m in _B64.finditer(text):
        try:
            dec = base64.b64decode(m.group(0) + '===', altchars=b'-_').decode('utf-8', 'ignore')
        except Exception:
            continue
        if dec.lower().startswith('http'):
            text += f'\n{dec}'
            tricks.append({'id': 'base64_link', 'label': 'Link hidden in base64 encoding', 'evidence': dec[:120]})
    return Normalized(text=text, tricks=tricks)
