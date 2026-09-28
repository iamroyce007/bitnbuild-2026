"""Lexical URL features shared by training and inference (single source of truth)."""
from __future__ import annotations

import math
import re
from collections import Counter

from ..utils.unicode_utils import is_mixed_script, to_unicode
from ..utils.url_utils import is_ip, parse_url

SUSPICIOUS_TLDS = {'xyz', 'top', 'online', 'site', 'club', 'shop', 'live', 'store', 'icu', 'buzz', 'vip', 'work', 'click', 'link', 'support', 'help',
                   'space', 'website', 'fun', 'win', 'bid', 'loan', 'rest', 'cyou', 'sbs', 'lol', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq', 'cc', 'ru', 'cn',
                   'info', 'monster', 'quest', 'bond', 'autos', 'beauty', 'hair', 'zip', 'mov', 'cam', 'today', 'digital', 'world', 'asia', 'pro'}
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc',
              'bitly.com', 's.id', 'v.gd', 'qrco.de', 'shorte.st', 'adf.ly', 'bl.ink', 'surl.li', 'urlz.fr', 'clck.ru', 'u.to', 'kutt.it', 'short.gy', 'lnkd.in'}
FREE_HOSTING = ('github.io', 'web.app', 'firebaseapp.com', 'pages.dev', 'vercel.app', 'netlify.app', 'herokuapp.com', 'blogspot.com', 'weebly.com',
                'wixsite.com', 'glitch.me', 'repl.co', 'ngrok.io', 'ngrok-free.app', 'trycloudflare.com', 'r2.dev', 'workers.dev', 'onrender.com',
                '000webhostapp.com', 'webflow.io', 'framer.app', 'ipfs.io', 'dweb.link', 'sites.google.com', 'forms.gle', 'firebasestorage.googleapis.com')
KEYWORDS = ('login', 'signin', 'sign-in', 'logon', 'verify', 'verification', 'secure', 'account', 'update', 'confirm', 'banking', 'password', 'wallet',
            'kyc', 'suspend', 'unlock', 'billing', 'invoice', 'webscr', 'auth', 'recover', 'reward', 'claim', 'refund', 'bonus', 'gift', 'free', 'otp')
SUSP_PARAMS = ('redirect', 'redir', 'url', 'next', 'continue', 'return', 'goto', 'dest', 'email', 'token', 'session', 'login_hint', 'rurl')

FEATURE_NAMES = [
    'url_len', 'host_len', 'path_len', 'query_len', 'n_dots', 'n_subdomains', 'digit_ratio', 'special_ratio', 'n_hyphens', 'n_underscores',
    'n_slashes', 'has_at', 'n_percent', 'is_ip', 'has_port', 'is_punycode', 'has_unicode', 'mixed_script', 'suspicious_tld', 'n_keywords',
    'is_shortener', 'free_hosting', 'host_entropy', 'path_entropy', 'hex_run', 'longest_token', 'random_path', 'n_susp_params', 'n_params',
    'double_slash_path', 'tld_len', 'n_host_digits', 'host_vowel_ratio', 'has_file_ext', 'exec_ext', 'n_embedded_domains', 'reg_len',
]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def url_features(url: str) -> dict[str, float]:
    p = parse_url(url)
    if p is None or not p.host:
        return {k: 0.0 for k in FEATURE_NAMES}
    u = p.normalized
    host = p.host
    path = p.path or ''
    q = p.query or ''
    tokens = re.split(r'[/\-._?=&]+', (path + '?' + q).lower())
    uni = to_unicode(host)
    reg_label = p.registrable.split('.')[0] if p.registrable else host
    f = {
        'url_len': len(u), 'host_len': len(host), 'path_len': len(path), 'query_len': len(q),
        'n_dots': host.count('.'), 'n_subdomains': len([s for s in p.subdomain.split('.') if s]),
        'digit_ratio': sum(c.isdigit() for c in u) / max(1, len(u)),
        'special_ratio': sum(not c.isalnum() for c in u) / max(1, len(u)),
        'n_hyphens': host.count('-'), 'n_underscores': u.count('_'), 'n_slashes': path.count('/'),
        'has_at': float('@' in u.split('?')[0] or bool(p.userinfo)), 'n_percent': u.count('%'),
        'is_ip': float(is_ip(host)), 'has_port': float(p.port not in (None, 80, 443)),
        'is_punycode': float('xn--' in host), 'has_unicode': float(not uni.isascii()),
        'mixed_script': float(any(is_mixed_script(l) for l in uni.split('.'))),
        'suspicious_tld': float(host.rsplit('.', 1)[-1] in SUSPICIOUS_TLDS),
        'n_keywords': float(sum(k in u.lower() for k in KEYWORDS)),
        'is_shortener': float(p.registrable in SHORTENERS or host in SHORTENERS),
        'free_hosting': float(any(host == h or host.endswith('.' + h) for h in FREE_HOSTING)),
        'host_entropy': entropy(host), 'path_entropy': entropy(path + q),
        'hex_run': float(max((len(m) for m in re.findall(r'[0-9a-f]{8,}', u.lower())), default=0)),
        'longest_token': float(max((len(t) for t in tokens), default=0)),
        'random_path': float(any(len(t) >= 12 and entropy(t) > 3.5 for t in tokens)),
        'n_susp_params': float(sum(1 for kv in q.lower().split('&') if kv.split('=')[0] in SUSP_PARAMS)),
        'n_params': float(len([x for x in q.split('&') if x])),
        'double_slash_path': float('//' in path),
        'tld_len': float(len(host.rsplit('.', 1)[-1])),
        'n_host_digits': float(sum(c.isdigit() for c in host)),
        'host_vowel_ratio': sum(c in 'aeiou' for c in reg_label) / max(1, len(reg_label)),
        'has_file_ext': float(bool(re.search(r'\.[a-z0-9]{2,4}$', path.lower()))),
        'exec_ext': float(bool(re.search(r'\.(exe|apk|scr|msi|bat|js|vbs|jar|iso|hta)$', path.lower()))),
        'n_embedded_domains': float(len(re.findall(r'(?:[a-z0-9-]+\.)+(?:com|net|org|in|co|io)\b', (path + q).lower()))),
        'reg_len': float(len(p.registrable)),
    }
    return f


def feature_vector(url: str) -> list[float]:
    f = url_features(url)
    return [float(f[k]) for k in FEATURE_NAMES]


def char_ngrams(url: str) -> list[str]:
    """Analyzer for the hashed character n-gram model (scheme and www. removed: they are dataset artifacts)."""
    s = url.strip().lower()
    s = re.sub(r'^[a-z]+://', '', s)
    s = re.sub(r'^www\.', '', s)
    s = s.rstrip('/')
    s = '^' + s[:200] + '$'
    return [s[i:i + n] for n in (3, 4, 5) for i in range(len(s) - n + 1)]
