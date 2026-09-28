"""URL parsing, normalisation and registrable-domain extraction using the full Public Suffix List."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import parse_qsl, unquote, urlsplit

from ..config import get_settings
from .unicode_utils import to_ascii, to_unicode


@lru_cache(maxsize=1)
def _psl() -> tuple[set[str], set[str], set[str]]:
    rules, wild, exc = set(), set(), set()
    with open(get_settings().data_dir / 'raw' / 'public_suffix_list.dat', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            line = to_ascii(line.split()[0])
            if line.startswith('!'):
                exc.add(line[1:])
            elif line.startswith('*.'):
                wild.add(line[2:])
            else:
                rules.add(line)
    return rules, wild, exc


@lru_cache(maxsize=200_000)
def split_host(host: str) -> tuple[str, str, str]:
    """-> (subdomain, registrable_domain, public_suffix). IPs return ('', ip, '')."""
    host = host.lower().strip('.')
    if is_ip(host):
        return '', host, ''
    rules, wild, exc = _psl()
    labels = host.split('.')
    suffix_len = 1
    for i in range(len(labels)):
        cand = '.'.join(labels[i:])
        if cand in exc:
            suffix_len = len(labels) - i - 1
            break
        if cand in rules:
            suffix_len = len(labels) - i
            break
        parent = '.'.join(labels[i + 1:])
        if parent and parent in wild:
            suffix_len = len(labels) - i
            break
    if suffix_len >= len(labels):
        return '', host, host
    reg = '.'.join(labels[-(suffix_len + 1):])
    sub = '.'.join(labels[:-(suffix_len + 1)])
    return sub, reg, '.'.join(labels[-suffix_len:])


def registrable(host: str) -> str:
    return split_host(host)[1]


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip('[]'))
        return True
    except ValueError:
        return bool(re.fullmatch(r'0x[0-9a-f]+|\d{8,10}', host))  # hex / dword IP obfuscation


# Wrappers that hide the real destination inside a query parameter
_WRAPPERS = {
    'safelinks.protection.outlook.com': 'url', 'www.google.com': 'q', 'google.com': 'q', 'l.facebook.com': 'u', 'lm.facebook.com': 'u',
    'urldefense.proofpoint.com': 'u', 'urldefense.com': None, 'l.instagram.com': 'u', 't.umblr.com': 'z', 'away.vk.com': 'to',
    'www.youtube.com': 'q', 'slack-redir.net': 'url', 'r.search.yahoo.com': None, 'click.linksynergy.com': 'murl', 'out.reddit.com': 'url',
}


def unwrap(url: str, depth: int = 0) -> list[str]:
    """Return the chain of URLs revealed by unwrapping tracking/safe-link redirectors (static, no network)."""
    chain = [url]
    if depth > 4:
        return chain
    try:
        p = urlsplit(url)
    except ValueError:
        return chain
    host = (p.hostname or '').lower()
    wrapper = host if host in _WRAPPERS else next((w for w in _WRAPPERS if host.endswith('.' + w)), None)  # e.g. nam02.safelinks...
    key = _WRAPPERS.get(wrapper) if wrapper else None
    if wrapper and (p.path.startswith('/url') or p.path.startswith('/l.php') or p.path.startswith('/redirect') or 'safelinks' in host or 'urldefense' in host or key):
        q = dict(parse_qsl(p.query))
        target = q.get(key) if key else None
        if 'urldefense.com' in host:
            m = re.search(r'__(https?:.+?)__;', url)
            target = m.group(1) if m else None
        if target and target.startswith(('http://', 'https://')):
            chain += unwrap(unquote(target), depth + 1)
    return chain


@dataclass
class ParsedURL:
    original: str
    normalized: str
    scheme: str
    host: str  # ascii / punycode form
    host_unicode: str
    subdomain: str
    registrable: str
    suffix: str
    port: int | None
    path: str
    query: str
    fragment: str
    userinfo: str
    unwrapped: list[str] = field(default_factory=list)


def parse_url(raw: str) -> ParsedURL | None:
    s = raw.strip().strip('<>"\'')
    if not s:
        return None
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', s):
        s = 'http://' + s
    try:
        p = urlsplit(s)
        port = p.port
    except ValueError:
        return None
    if p.scheme.lower() not in ('http', 'https', 'ftp'):
        return ParsedURL(raw, s, p.scheme.lower(), '', '', '', '', '', None, p.path, p.query, p.fragment, '')
    host_raw = (p.hostname or '').rstrip('.')
    if not host_raw:
        return None
    host = to_ascii(host_raw)
    sub, reg, suf = split_host(host)
    userinfo = p.netloc.rsplit('@', 1)[0] if '@' in p.netloc else ''
    netloc = host + (f':{port}' if port and port not in (80, 443) else '')
    normalized = f'{p.scheme.lower()}://{netloc}{p.path or "/"}' + (f'?{p.query}' if p.query else '')
    return ParsedURL(raw, normalized, p.scheme.lower(), host, to_unicode(host), sub, reg, suf, port, p.path or '/', p.query, p.fragment, userinfo, unwrap(normalized)[1:])


PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
    '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32',
    '::1/128', '::/128', 'fc00::/7', 'fe80::/10', 'ff00::/8', '::ffff:0:0/96')]


def is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    return not any(a in n for n in PRIVATE_NETS)


BLOCKED_HOSTNAMES = {'localhost', 'localhost.localdomain', 'metadata.google.internal', 'metadata', 'instance-data'}


def ssrf_block_reason(host: str) -> str | None:
    """Static check before any network activity. DNS results are re-checked at connect time."""
    h = host.lower().strip('[].')
    if h in BLOCKED_HOSTNAMES or h.endswith(('.localhost', '.internal', '.local', '.lan', '.home.arpa', '.corp')):
        return f'internal hostname {h}'
    if is_ip(h):
        try:
            if not is_public_ip(h):
                return f'private/reserved address {h}'
        except Exception:
            return f'obfuscated IP literal {h}'
        if re.fullmatch(r'0x[0-9a-f]+|\d{8,10}', h):
            return f'obfuscated IP literal {h}'
    return None
