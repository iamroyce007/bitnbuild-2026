"""Find every URL a message can send someone to: plain text, bare domains, HTML links, buttons, forms,
meta refresh, base64, safe-link wrappers. Deduplicated, normalised, with provenance."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import unquote

from ..utils.url_utils import ParsedURL, parse_url

TLDS = ('com|net|org|in|co|io|info|xyz|top|me|ly|biz|online|site|club|link|app|shop|live|store|tech|cc|ru|cn|tk|ml|ga|cf|gq|buzz|icu|vip|work|'
        'click|today|support|help|space|website|fun|win|bid|loan|rest|cyou|sbs|lol|pw|ws|ai|gov|edu|us|uk|dev|page|cloud|digital|world|asia|mobi|pro|tv|'
        'de|fr|br|au|ca|jp|it|nl|es|pl|id|vn|ph|pk|bd|lk|np|ae|sa|za|ng|ke|eu|monster|quest|bond|zip|mov|cam|sbi|google|bank|email|services|center|network')
RE_URL = re.compile(rf'(?:(?:https?|ftp)://[^\s<>"\'\)\]\}}]+|\b(?:www\.)?(?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]{{0,61}}[a-z0-9¡-￿])?\.)+(?:{TLDS})\b(?::\d{{2,5}})?(?:/[^\s<>"\'\)\]\}}]*)?)', re.I)
RE_EMAIL = re.compile(r'\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b', re.I)


@dataclass
class ExtractedURL:
    url: ParsedURL
    sources: list[str] = field(default_factory=list)  # text | href | button | form | redirect | base64 | unwrapped
    display_text: str | None = None
    deceptive_text: str | None = None  # link text shows a different domain than the real target


def extract_urls(text: str, anchors: list[dict] | None = None, forms: list[str] | None = None, limit: int = 40) -> list[ExtractedURL]:
    found: dict[str, ExtractedURL] = {}

    def add(raw: str, src: str, shown: str | None = None) -> None:
        raw = raw.strip().rstrip('.,;:!?\'")]}>')
        if not raw or raw.startswith(('mailto:', 'tel:', '#', 'cid:')):
            return
        if raw.lower().startswith(('javascript:', 'data:')):
            p = parse_url(raw)
            if p:
                found.setdefault(raw[:80], ExtractedURL(p, [src]))
            return
        p = parse_url(unquote(raw) if '%3a%2f%2f' in raw.lower() else raw)
        if not p or (not p.host and p.scheme in ('http', 'https')):
            return
        e = found.get(p.normalized)
        if e is None:
            e = found[p.normalized] = ExtractedURL(p, [])
        if src not in e.sources:
            e.sources.append(src)
        if shown and not e.display_text:
            e.display_text = shown[:200]
            m = RE_URL.search(shown)
            if m:
                sp = parse_url(m.group(0))
                if sp and sp.registrable and p.registrable and sp.registrable != p.registrable:
                    e.deceptive_text = f'link text shows "{sp.host}" but it actually opens {p.host}'
        for inner in p.unwrapped:
            add(inner, 'unwrapped')

    for a in anchors or []:
        add(a['href'], 'button' if a.get('text', '').startswith('[') else 'href', a.get('text'))
    for f in forms or []:
        add(f, 'form')
    clean = RE_EMAIL.sub(' ', text)
    for m in RE_URL.finditer(clean):
        add(m.group(0), 'text')
    return list(found.values())[:limit]


RE_PHONE = re.compile(r'(?:\+?91[\s-]?)?(?<!\d)[6-9]\d{4}[\s-]?\d{5}(?!\d)|\b1[89]00[\s-]?\d{3}[\s-]?\d{3,4}\b|\+\d{1,3}[\s-]?\d{3,4}[\s-]?\d{3,4}[\s-]?\d{2,4}')
RE_UPI = re.compile(r'\b[a-z0-9._-]{2,64}@(?:okaxis|okhdfcbank|oksbi|okicici|ybl|ibl|axl|paytm|apl|upi|sbi|icici|hdfcbank|axisbank|kotak|yesbank|idfcbank|federal|indus|rbl|jupiteraxis|fam|freecharge|airtel|jio|pnb|boi|cnrb|unionbank|iob|indianbank)\b', re.I)
RE_BTC = re.compile(r'\b(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')


def extract_indicators(text: str) -> dict:
    upis = sorted({u.lower() for u in RE_UPI.findall(text)})
    emails = sorted({e.lower() for e in RE_EMAIL.findall(text)} - set(upis))
    return {
        'emails': emails[:20],
        'phones': sorted({re.sub(r'[\s-]', '', p) for p in RE_PHONE.findall(text)})[:10],
        'upi_ids': upis[:10],
        'crypto_wallets': sorted(set(RE_BTC.findall(text)))[:5],
    }
