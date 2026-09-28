"""Public-infrastructure enrichment that needs no API key: DNS (A/AAAA/NS/MX), ASN (Team Cymru DNS),
RDAP registration dates, and the TLS certificate the server presents. Every network step is SSRF-guarded:
hostnames resolving to private/reserved ranges are never contacted."""
from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import ssl
from datetime import datetime, timezone

import httpx

from ..config import get_settings
from .cache import get_cache
from .url_utils import is_ip, is_public_ip, ssrf_block_reason

TTL = 6 * 3600


def _resolver():
    import dns.asyncresolver
    r = dns.asyncresolver.Resolver()
    r.lifetime = 3.0
    r.timeout = 2.0
    return r


async def resolve(host: str) -> dict:
    key = f'dns:{host}'
    c = get_cache().get(key)
    if c is not None:
        return c
    out: dict = {'a': [], 'aaaa': [], 'ns': [], 'mx': [], 'error': None}
    try:
        r = _resolver()
        for rtype, field in (('A', 'a'), ('AAAA', 'aaaa'), ('NS', 'ns'), ('MX', 'mx')):
            try:
                ans = await r.resolve(host if rtype in ('A', 'AAAA') else host, rtype)
                vals = [str(x).rstrip('.').lower() for x in ans]
                out[field] = [v.split()[-1] if rtype == 'MX' else v for v in vals][:8]
            except Exception:
                pass
        if not out['ns']:  # NS usually lives on the registrable domain
            from .url_utils import registrable
            reg = registrable(host)
            if reg != host:
                try:
                    out['ns'] = [str(x).rstrip('.').lower() for x in await r.resolve(reg, 'NS')][:8]
                except Exception:
                    pass
    except Exception as e:
        out['error'] = str(e)[:120]
    get_cache().set(key, out, TTL)
    return out


async def asn_for_ip(ip: str) -> dict | None:
    """ASN / prefix / country via Team Cymru's DNS interface (origin.asn.cymru.com)."""
    if not is_public_ip(ip) or ':' in ip:
        return None
    key = f'asn:{ip}'
    c = get_cache().get(key)
    if c is not None:
        return c
    try:
        r = _resolver()
        q = '.'.join(reversed(ip.split('.'))) + '.origin.asn.cymru.com'
        txt = str((await r.resolve(q, 'TXT'))[0]).strip('"')
        asn, prefix, cc, *_ = [p.strip() for p in txt.split('|')]
        name = ''
        try:
            t2 = str((await r.resolve(f'AS{asn.split()[0]}.asn.cymru.com', 'TXT'))[0]).strip('"')
            name = t2.split('|')[-1].strip()
        except Exception:
            pass
        out = {'asn': f'AS{asn.split()[0]}', 'prefix': prefix, 'country': cc, 'name': name, 'source': 'team-cymru'}
    except Exception:
        out = None
    get_cache().set(key, out, TTL)
    return out


async def rdap(domain: str) -> dict | None:
    """Registration / expiry dates and registrar from RDAP (rdap.org bootstrap)."""
    key = f'rdap:{domain}'
    c = get_cache().get(key)
    if c is not None:
        return c
    out = None
    try:
        async with httpx.AsyncClient(timeout=get_settings().ti_timeout_s, follow_redirects=True, headers={'accept': 'application/rdap+json'}) as cl:
            r = await cl.get(f'https://rdap.org/domain/{domain}')
            if r.status_code == 200:
                j = r.json()
                ev = {e.get('eventAction'): e.get('eventDate') for e in j.get('events', [])}
                registrar = ''
                for ent in j.get('entities', []):
                    if 'registrar' in ent.get('roles', []):
                        v = ent.get('vcardArray', [None, []])[1]
                        registrar = next((x[3] for x in v if x[0] == 'fn'), '')
                created = ev.get('registration')
                age = None
                if created:
                    try:
                        age = (datetime.now(timezone.utc) - datetime.fromisoformat(created.replace('Z', '+00:00'))).days
                    except Exception:
                        pass
                out = {'created': created, 'expires': ev.get('expiration'), 'updated': ev.get('last changed'), 'registrar': registrar,
                       'age_days': age, 'status': j.get('status', [])[:6], 'source': 'rdap.org'}
            elif r.status_code == 404:
                out = {'not_found': True, 'source': 'rdap.org'}
    except Exception:
        out = None
    get_cache().set(key, out, TTL if out else 600)
    return out


def _tls_cert_sync(host: str, ip: str) -> dict | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, 443), timeout=4) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            der = ss.getpeercert(binary_form=True)
    if not der:
        return None
    from cryptography import x509
    cert = x509.load_der_x509_certificate(der)
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except Exception:
        sans = []
    nb = cert.not_valid_before_utc
    return {'sha256': hashlib.sha256(der).hexdigest(), 'issuer': cert.issuer.rfc4514_string()[:200], 'subject': cert.subject.rfc4514_string()[:200],
            'not_before': nb.isoformat(), 'not_after': cert.not_valid_after_utc.isoformat(), 'age_days': (datetime.now(timezone.utc) - nb).days,
            'san': sans[:50], 'self_signed': cert.issuer == cert.subject, 'source': 'tls-handshake'}


async def tls_cert(host: str, ip: str) -> dict | None:
    """Fetch the certificate only; no HTTP request is sent. Refuses non-public IPs (SSRF guard)."""
    if not is_public_ip(ip) and not get_settings().allow_private_targets:
        return None
    key = f'tls:{host}:{ip}'
    c = get_cache().get(key)
    if c is not None:
        return c
    try:
        out = await asyncio.wait_for(asyncio.to_thread(_tls_cert_sync, host, ip), timeout=6)
    except Exception:
        out = None
    get_cache().set(key, out, TTL if out else 900)
    return out


_DEMO: dict | None = None


def demo_infrastructure() -> dict:
    """Fictional infrastructure for the seeded demo domains (RFC 5737 IPs, RFC 5398 ASNs), labelled DEMO DATA."""
    global _DEMO
    if _DEMO is None:
        p = get_settings().data_dir / 'demo' / 'demo_dataset.json'
        _DEMO = json.loads(p.read_text())['infrastructure'] if p.exists() else {}
    return _DEMO


def _demo_enrichment(host: str, d: dict) -> dict:
    from .url_utils import registrable
    from datetime import timedelta
    created = (datetime.now(timezone.utc) - timedelta(days=d['age_days'])).isoformat(timespec='seconds')
    return {'host': host, 'registrable': registrable(host), 'demo': True,
            'status': {'dns': 'DEMO DATA', 'rdap': 'DEMO DATA', 'tls': 'DEMO DATA'},
            'dns': {'a': [d['ip']], 'aaaa': [], 'ns': d['ns'], 'mx': []},
            'asn': [{'asn': d['asn'], 'name': d['asn_name'], 'country': 'ZZ', 'prefix': d['ip'].rsplit('.', 1)[0] + '.0/24', 'source': 'DEMO DATA'}],
            'rdap': {'created': created, 'age_days': d['age_days'], 'registrar': d['registrar'], 'source': 'DEMO DATA'},
            'tls': {'sha256': hashlib.sha256(d['cert'].encode()).hexdigest(), 'issuer': 'CN=Demo Free CA', 'subject': f'CN={host}',
                    'not_before': created, 'age_days': d['age_days'], 'san': [host], 'self_signed': False, 'source': 'DEMO DATA'}}


async def enrich_host(host: str) -> dict:
    """Parallel DNS -> (ASN per IP, TLS cert) + RDAP. Returns what was actually observed, with per-step status."""
    from .url_utils import registrable
    s = get_settings()
    if s.demo_mode and host in demo_infrastructure():
        return _demo_enrichment(host, demo_infrastructure()[host])
    blocked = ssrf_block_reason(host)
    res: dict = {'host': host, 'registrable': registrable(host), 'status': {}}
    if blocked and not s.allow_private_targets:
        res['status']['ssrf'] = f'blocked: {blocked}'
        return res
    if not s.enable_active_enrichment:
        res['status']['enrichment'] = 'disabled'
        return res
    if is_ip(host):
        dns_res = {'a': [host] if ':' not in host else [], 'aaaa': [host] if ':' in host else [], 'ns': [], 'mx': []}
    else:
        dns_res, rd = await asyncio.gather(resolve(host), rdap(registrable(host)))
        res['rdap'] = rd
        res['status']['rdap'] = 'ok' if rd else 'unavailable'
    res['dns'] = dns_res
    res['status']['dns'] = 'ok' if dns_res.get('a') or dns_res.get('aaaa') else 'no-records'
    public = [ip for ip in dns_res.get('a', []) if is_public_ip(ip)]
    private = [ip for ip in dns_res.get('a', []) if not is_public_ip(ip)]
    if private:
        res['status']['ssrf'] = f'resolves to non-public address(es) {private[:3]}; not contacted'
    if public:
        asns = await asyncio.gather(*(asn_for_ip(ip) for ip in public[:3]))
        res['asn'] = [a for a in asns if a]
        res['tls'] = await tls_cert(host, public[0])
        res['status']['tls'] = 'ok' if res['tls'] else 'unavailable'
    return res
