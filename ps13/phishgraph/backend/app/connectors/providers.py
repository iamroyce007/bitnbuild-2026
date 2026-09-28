"""Provider implementations. Each maps a real API response to a TIResult; nothing is invented when a field is absent."""
from __future__ import annotations

import base64

from ..config import get_settings
from .base import Connector, TIResult


class VirusTotal(Connector):
    name = 'virustotal'
    supports = ('url', 'domain', 'ip', 'hash')
    key_setting = 'virustotal_api_key'
    rate_per_min = 4  # public API quota

    async def _lookup(self, t: str, v: str) -> TIResult:
        path = {'url': f'urls/{base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")}', 'domain': f'domains/{v}', 'ip': f'ip_addresses/{v}', 'hash': f'files/{v}'}[t]
        async with self.client(headers={'x-apikey': self.api_key}) as c:
            r = await c.get(f'https://www.virustotal.com/api/v3/{path}')
            if r.status_code == 404:
                return self._res(t, v, 'ok', verdict='unknown', summary='not present in VirusTotal', confidence=0.2)
            r.raise_for_status()
            a = r.json()['data']['attributes']
        st = a.get('last_analysis_stats', {})
        mal, sus = st.get('malicious', 0), st.get('suspicious', 0)
        total = sum(st.values()) or 1
        risk = min(100.0, 100 * (mal + 0.5 * sus) / max(8, total * 0.25))
        verdict = 'malicious' if mal >= 3 else 'suspicious' if mal + sus >= 1 else 'clean'
        rel = []
        if t == 'domain':
            for rec in a.get('last_dns_records', [])[:10]:
                if rec.get('type') == 'A':
                    rel.append({'rel': 'RESOLVES_TO', 'type': 'ip', 'value': rec.get('value')})
                if rec.get('type') == 'NS':
                    rel.append({'rel': 'USES_NS', 'type': 'nameserver', 'value': rec.get('value', '').rstrip('.')})
        return self._res(t, v, 'ok', verdict=verdict, risk=risk, confidence=0.9 if total > 20 else 0.6,
                         summary=f'{mal} of {total} engines flag it malicious, {sus} suspicious',
                         details={'stats': st, 'reputation': a.get('reputation'), 'categories': a.get('categories', {}), 'creation_date': a.get('creation_date')}, relations=rel)


class URLScan(Connector):
    name = 'urlscan'
    supports = ('url', 'domain', 'ip')
    key_setting = 'urlscan_api_key'
    rate_per_min = 20

    async def _lookup(self, t: str, v: str) -> TIResult:
        from ..utils.url_utils import parse_url
        q = {'domain': f'domain:{v}', 'ip': f'ip:"{v}"', 'url': f'page.domain:{parse_url(v).host if parse_url(v) else v}'}[t]
        async with self.client(headers={'API-Key': self.api_key}) as c:  # search history first (no new scan, no quota burn)
            r = await c.get('https://urlscan.io/api/v1/search/', params={'q': q, 'size': 50})
            r.raise_for_status()
            res = r.json().get('results', [])
            submitted = None
            if not res and t == 'url' and get_settings().urlscan_submit:
                s = await c.post('https://urlscan.io/api/v1/scan/', json={'url': v, 'visibility': get_settings().urlscan_visibility})
                if s.status_code < 300:
                    submitted = s.json().get('uuid')
        mal = sum(1 for x in res if (x.get('verdicts') or {}).get('overall', {}).get('malicious'))
        rel, seen = [], set()
        for x in res:
            p = x.get('page', {})
            for rel_t, typ, val in (('RESOLVES_TO', 'ip', p.get('ip')), ('BELONGS_TO', 'asn', p.get('asn')), ('OBSERVED_DOMAIN', 'domain', p.get('domain'))):
                if val and (typ, val) not in seen:
                    seen.add((typ, val))
                    rel.append({'rel': rel_t, 'type': typ, 'value': str(val), 'first_seen': x.get('task', {}).get('time')})
        verdict = 'malicious' if mal else 'unknown' if not res else 'clean'
        return self._res(t, v, 'ok', verdict=verdict, risk=min(100, 40 + 20 * mal) if mal else 0, confidence=0.7 if res else 0.2,
                         summary=f'{len(res)} historical scans, {mal} marked malicious' + (f'; new scan submitted ({submitted})' if submitted else ''),
                         details={'scans': len(res), 'malicious_scans': mal, 'screenshot': res[0].get('screenshot') if res else None, 'submitted_uuid': submitted},
                         relations=rel[:40])


class AbuseIPDB(Connector):
    name = 'abuseipdb'
    supports = ('ip',)
    key_setting = 'abuseipdb_api_key'
    rate_per_min = 30

    async def _lookup(self, t: str, v: str) -> TIResult:
        async with self.client(headers={'Key': self.api_key, 'Accept': 'application/json'}) as c:
            r = await c.get('https://api.abuseipdb.com/api/v2/check', params={'ipAddress': v, 'maxAgeInDays': 90})
            r.raise_for_status()
            d = r.json()['data']
        conf = d.get('abuseConfidenceScore', 0)
        return self._res(t, v, 'ok', verdict='malicious' if conf >= 75 else 'suspicious' if conf >= 25 else 'clean', risk=float(conf), confidence=0.6,
                         summary=f'abuse confidence {conf}%, {d.get("totalReports", 0)} reports',
                         details={k: d.get(k) for k in ('abuseConfidenceScore', 'totalReports', 'countryCode', 'isp', 'usageType', 'domain', 'lastReportedAt')})


class OTX(Connector):
    name = 'otx'
    supports = ('url', 'domain', 'ip', 'hash')
    key_setting = 'otx_api_key'
    rate_per_min = 60

    async def _lookup(self, t: str, v: str) -> TIResult:
        sec = {'url': 'url', 'domain': 'domain', 'ip': 'IPv4', 'hash': 'file'}[t]
        async with self.client(headers={'X-OTX-API-KEY': self.api_key}) as c:
            r = await c.get(f'https://otx.alienvault.com/api/v1/indicators/{sec}/{v}/general')
            if r.status_code == 404:
                return self._res(t, v, 'ok', summary='unknown to OTX', confidence=0.2)
            r.raise_for_status()
            j = r.json()
        pulses = j.get('pulse_info', {}).get('count', 0)
        names = [p.get('name') for p in j.get('pulse_info', {}).get('pulses', [])[:5]]
        return self._res(t, v, 'ok', verdict='malicious' if pulses >= 3 else 'suspicious' if pulses else 'unknown', risk=min(100, pulses * 20), confidence=0.6,
                         summary=f'referenced by {pulses} OTX pulse(s)', details={'pulses': pulses, 'pulse_names': names})


class SafeBrowsing(Connector):
    name = 'google_safe_browsing'
    supports = ('url',)
    key_setting = 'google_safe_browsing_api_key'
    rate_per_min = 100

    async def _lookup(self, t: str, v: str) -> TIResult:
        body = {'client': {'clientId': 'phishgraph', 'clientVersion': '1.0'},
                'threatInfo': {'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                               'platformTypes': ['ANY_PLATFORM'], 'threatEntryTypes': ['URL'], 'threatEntries': [{'url': v}]}}
        async with self.client() as c:
            r = await c.post(f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}', json=body)
            r.raise_for_status()
            m = r.json().get('matches', [])
        types = sorted({x.get('threatType') for x in m})
        return self._res(t, v, 'ok', verdict='malicious' if m else 'unknown', risk=95.0 if m else 0.0, confidence=0.95 if m else 0.3,
                         summary=f'listed as {", ".join(types)}' if m else 'not on Safe Browsing lists', details={'threat_types': types})


class URLhaus(Connector):
    name = 'urlhaus'
    supports = ('url', 'domain', 'ip')
    key_setting = 'urlhaus_auth_key'
    rate_per_min = 60

    async def _lookup(self, t: str, v: str) -> TIResult:
        ep, data = ('url', {'url': v}) if t == 'url' else ('host', {'host': v})
        async with self.client(headers={'Auth-Key': self.api_key}) as c:
            r = await c.post(f'https://urlhaus-api.abuse.ch/v1/{ep}/', data=data)
            r.raise_for_status()
            j = r.json()
        if j.get('query_status') not in ('ok', 'is_host'):
            return self._res(t, v, 'ok', summary='not in URLhaus', confidence=0.3)
        n = len(j.get('urls', [])) if ep == 'host' else 1
        return self._res(t, v, 'ok', verdict='malicious', risk=90.0, confidence=0.85, summary=f'URLhaus: {n} malware URL(s) ({j.get("threat") or "malware"})',
                         details={'threat': j.get('threat'), 'tags': j.get('tags'), 'url_count': n})


class LocalIntel(Connector):
    """Local IOC store: OpenPhish / PhishTank / URLhaus feed ingestion, analyst-confirmed IOCs, demo seeds."""
    name = 'local_intel'
    supports = ('url', 'domain', 'ip', 'hash')
    external = False
    ttl = 0  # in-memory store: always live, so analyst confirmations take effect immediately

    async def _lookup(self, t: str, v: str) -> TIResult:
        from ..services.intel_store import get_intel_store
        hits = get_intel_store().match(t, v)
        if not hits:
            return self._res(t, v, 'ok', summary='no match in local feeds', confidence=0.3, details={'feed_size': get_intel_store().size()})
        srcs = sorted({h['source'] for h in hits})
        exact = any(h['match'] == 'exact' for h in hits)
        demo = all(h.get('demo') for h in hits)
        return self._res(t, v, 'ok', verdict='malicious', risk=95.0 if exact else 70.0, confidence=0.95 if exact else 0.7,
                         summary=f'{"exact" if exact else "domain-level"} match in {", ".join(srcs)}' + (' (DEMO DATA)' if demo else ''),
                         details={'hits': hits[:5], 'demo': demo})


ALL = [LocalIntel, VirusTotal, URLScan, SafeBrowsing, OTX, AbuseIPDB, URLhaus]
