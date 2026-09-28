"""Brand impersonation & look-alike domain engine.

Protects every curated brand plus the top-N domains of the Tranco list against:
  homograph      gооgle.com (Cyrillic), g00gle.com, rnicrosoft.com      -> equal UTS#39 skeletons
  typosquat      gogle.com, googel.com, paypall.com                     -> Damerau-Levenshtein 1-2 via a deletion index
  combosquat     sbi-kyc-update.online, paypal-secure-login.com         -> curated brand token inside a foreign domain
  subdomain spoof google.com.verify-account.xyz                          -> protected domain used as a subdomain prefix
  TLD swap       paypal.xyz                                             -> exact brand label on an unrelated suffix

False-positive guards (the "no hallucination" rules):
  * the brand's own official domains and every subdomain of them are never flagged
  * any domain inside the Tranco top `tranco_established_top` is treated as established and never flagged as a look-alike
  * edit-distance matching is only applied to protected labels of >=5 characters (short labels collide by chance)
  * every finding carries the exact evidence string it was derived from
"""
from __future__ import annotations

import csv
import difflib
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache

from ..config import get_settings
from ..utils.unicode_utils import is_mixed_script, scripts_in, skeleton, to_unicode
from ..utils.url_utils import is_ip, split_host


@dataclass
class Brand:
    id: str
    name: str
    category: str
    domains: list[str]
    keywords: list[str]


@dataclass
class Finding:
    kind: str  # homograph | substitution | typosquat | combosquat | subdomain_spoof | tld_swap
    target_domain: str
    brand: str | None
    confidence: float
    evidence: str


@dataclass
class DomainVerdict:
    host: str
    host_unicode: str
    registrable: str
    official_brand: str | None = None
    tranco_rank: int | None = None
    established: bool = False
    mixed_script: bool = False
    scripts: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def impersonated(self) -> str | None:
        return self.findings[0].brand or self.findings[0].target_domain if self.findings else None

    @property
    def score(self) -> float:
        return max((f.confidence for f in self.findings), default=0.0)


def _dl(a: str, b: str, cap: int = 3) -> int:
    """Damerau-Levenshtein (optimal string alignment) with early exit."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev2 = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            c = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + c)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > cap:
            return cap + 1
        prev2, prev = prev, cur
    return prev[-1]


def tkey(s: str) -> str:
    """Typo-comparison key: visual skeleton, with the multi-char 'rn' folded back to 'm' so it costs one edit."""
    return skeleton(s).replace('rn', 'm')


def _deletes(s: str) -> set[str]:
    return {s[:i] + s[i + 1:] for i in range(len(s))}


# words attackers glue onto brand names; a brand prefix/suffix only counts when the rest is one of these
SCAM_AFFIXES = {'secure', 'security', 'login', 'signin', 'logon', 'verify', 'verification', 'account', 'accounts', 'support', 'update', 'help',
                'helpdesk', 'billing', 'service', 'services', 'online', 'bank', 'banking', 'pay', 'payment', 'kyc', 'id', 'auth', 'alert', 'alerts',
                'center', 'centre', 'portal', 'team', 'official', 'india', 'in', 'app', 'web', 'mail', 'cloud', 'wallet', 'reward', 'rewards',
                'refund', 'gift', 'offer', 'offers', 'care', 'desk', 'unlock', 'recovery', 'restore', 'confirm', 'check', 'safe', 'protect',
                'notice', 'claim', 'bonus', 'prize', 'customer', 'net', 'netbanking', 'my', 'get', 'go', 'www', 'sso', 'access', 'document',
                'docs', 'invoice', 'delivery', 'track', 'tracking', 'parcel', 'redeem', 'points', 'upi', 'cashback', 'reactivate', 'block', 'blocked'}
# brand keywords that are also everyday words: alone they are weak evidence
COMMON_WORD_KEYWORDS = {'apple', 'amazon', 'slack', 'meta', 'steam', 'yono', 'upi', 'uan', 'telegram', 'messenger', 'outlook', 'acrobat'}

TOKEN_SPLIT = re.compile(r'[.\-_]+|(?<=[a-z])(?=\d)|(?<=\d)(?=[a-z])')


class BrandEngine:
    def __init__(self) -> None:
        s = get_settings()
        raw = json.loads((s.data_dir / 'brands.json').read_text())
        self.brands = [Brand(**b) for b in raw['brands']]
        self.official: dict[str, Brand] = {}
        for b in self.brands:
            for d in b.domains:
                self.official.setdefault(d.lower(), b)
        self.rank: dict[str, int] = {}
        tranco = s.data_dir / 'raw' / 'top-1m.csv'
        if tranco.exists():
            with open(tranco, newline='') as f:
                for row in csv.reader(f):
                    r, d = int(row[0]), row[1].lower()
                    reg = split_host(d)[1] if r <= s.tranco_established_top else d
                    if reg not in self.rank:
                        self.rank[reg] = r
        self.established_top = s.tranco_established_top
        # protected labels: curated brands (any length >=4) + Tranco top-N (>=5 chars)
        self.protected: dict[str, tuple[str, str | None, int]] = {}  # label -> (domain, brand, priority)
        for b in self.brands:
            for d in b.domains:
                sub, reg, suf = split_host(d)
                lab = reg[: -len(suf) - 1] if suf and reg != suf else reg
                if len(lab) >= 3:
                    self.protected.setdefault(lab, (reg, b.name, 0))
        for d, r in sorted(self.rank.items(), key=lambda kv: kv[1]):
            if r > s.tranco_protect_top:
                break
            sub, reg, suf = split_host(d)
            lab = reg[: -len(suf) - 1] if suf and reg != suf else reg
            if len(lab) >= 5 and lab not in self.protected and lab.isascii():
                self.protected[lab] = (reg, None, r)
        self.protected_domains = {v[0] for v in self.protected.values()}
        self.skel_index: dict[str, list[str]] = {}
        self.del_index: dict[str, set[str]] = {}
        for lab in self.protected:
            self.skel_index.setdefault(skeleton(lab), []).append(lab)
            if len(lab) >= 5:
                tk = tkey(lab)
                self.del_index.setdefault(tk, set()).add(lab)
                for d in _deletes(tk):
                    self.del_index.setdefault(d, set()).add(lab)
        self.keywords: list[tuple[str, Brand, int]] = sorted(((skeleton(k), b, len(k)) for b in self.brands for k in b.keywords), key=lambda kb: -kb[2])

    # ------------------------------------------------------------------
    def official_brand(self, host: str) -> Brand | None:
        h = host.lower().rstrip('.')
        for i in range(h.count('.') + 1):
            cand = h.split('.', i)[-1]
            if cand in self.official:
                return self.official[cand]
        return None

    def _describe(self, lab: str) -> tuple[str, str | None]:
        dom, brand, _ = self.protected[lab]
        return dom, brand

    def analyze(self, host: str) -> DomainVerdict:
        host = host.lower().rstrip('.')
        sub, reg, suf = split_host(host)
        uni = to_unicode(host)
        v = DomainVerdict(host=host, host_unicode=uni, registrable=reg)
        if is_ip(host):
            return v
        b = self.official_brand(host)
        if b:
            v.official_brand = b.name
            return v
        v.tranco_rank = self.rank.get(reg)
        v.established = v.tranco_rank is not None and v.tranco_rank <= self.established_top
        reg_uni = to_unicode(reg)
        suf_len = len(to_unicode(suf)) + 1 if suf and reg != suf else 0
        label = reg_uni[:-suf_len] if suf_len else reg_uni
        v.mixed_script = is_mixed_script(label)
        v.scripts = sorted(scripts_in(label))
        if v.established:
            return v  # never call an established top-100k site a look-alike

        found: list[Finding] = []
        sk = skeleton(label)
        # (a) homograph / substitution / TLD swap: identical skeleton to a protected label
        for lab in self.skel_index.get(sk, []):
            dom, brand = self._describe(lab)
            if label == lab:
                if brand:  # generic words reused on other TLDs are normal; only curated brands count
                    cc = len(suf) == 2 or (suf.count('.') == 1 and len(suf.split('.')[-1]) == 2)
                    found.append(Finding('tld_swap', dom, brand, 0.5 if cc else 0.85,
                                         f'"{reg_uni}" reuses the exact name "{lab}" of {dom} on a different suffix'))
            elif not label.isascii():
                odd = ', '.join(sorted({f'{c} (U+{ord(c):04X})' for c in label if not c.isascii()}))[:120]
                found.append(Finding('homograph', dom, brand, 0.97,
                                     f'"{label}" renders like "{lab}" using look-alike characters {odd}'))
            else:
                ops = difflib.SequenceMatcher(None, label, lab, autojunk=False).get_opcodes()
                diffs = ', '.join(f'"{label[i1:i2]}"→"{lab[j1:j2]}"' for op, i1, i2, j1, j2 in ops if op != 'equal')[:80] or 'character swap'
                found.append(Finding('substitution', dom, brand, 0.95,
                                     f'"{label}" imitates "{lab}" by swapping look-alike characters ({diffs})'))
        # (b) typosquat: edit distance on skeletons, via the deletion index
        tk = tkey(label)
        if not found and len(tk) >= 5:
            cands: set[str] = set(self.del_index.get(tk, set()))
            for d in _deletes(tk):
                cands |= self.del_index.get(d, set())
            best = None
            for lab in cands:
                dom, brand, prio = self.protected[lab]
                sl = tkey(lab)
                dist = _dl(tk, sl, 2)
                if brand:  # curated brand: typos of 5+ char names, 2 edits allowed for long names
                    limit = 2 if len(lab) >= 9 else 1
                else:  # generic popular site: only 1 edit, only long names, no plural/suffix variants
                    limit = 1 if len(lab) >= 7 else 0
                    if tk.rstrip('s') == sl.rstrip('s') or tk.startswith(sl) or sl.startswith(tk):
                        limit = 0
                if 0 < dist <= limit:
                    key = (0 if brand else 1, dist, prio)
                    if best is None or key < best[0]:
                        best = (key, lab, dist)
            if best:
                _, lab, dist = best
                dom, brand = self._describe(lab)
                if brand:
                    conf = (0.88 if dist == 1 else 0.72) if len(lab) >= 6 else 0.62  # 5-letter names collide by chance
                else:
                    conf = 0.62  # generic popular site: weak evidence on its own, fused with other signals
                found.append(Finding('typosquat', dom, brand, conf,
                                     f'"{label}" is {dist} keystroke{"s" if dist > 1 else ""} away from "{lab}" ({dom})'))
        # (c) subdomain spoof: a protected domain appears as leading labels, e.g. google.com.verify.xyz
        if sub:
            parts = to_unicode(sub).split('.')
            for i in range(len(parts)):
                for j in range(i + 2, min(len(parts), i + 4) + 1):
                    cand = '.'.join(parts[i:j])
                    if cand in self.official or cand in self.protected_domains:
                        brand = self.official[cand].name if cand in self.official else None
                        found.append(Finding('subdomain_spoof', cand, brand, 0.93,
                                             f'"{cand}" is only a subdomain here; the real site is {reg_uni}'))
                        break
                else:
                    continue
                break
        # (d) combosquat: curated brand keyword embedded in someone else's domain (exact, affix, or 1 typo away)
        if not any(f.brand for f in found):
            raw_tokens = [t for t in re.split(r'[.\-_]+', uni) if t]
            raw_tokens += [t for t in TOKEN_SPLIT.split(uni) if t and t not in raw_tokens]
            toks = [(r, skeleton(r)) for r in raw_tokens]
            match = None
            skel_all = {t for _, t in toks}
            scammy = bool(skel_all & SCAM_AFFIXES)
            for kw, brand, kwlen in self.keywords:
                for r, t in toks:
                    rest = t[len(kw):] if t.startswith(kw) else t[:-len(kw)] if t.endswith(kw) else None
                    if t == kw:
                        match = (r, brand, 'exact')
                    elif kwlen >= 4 and rest and (rest in SCAM_AFFIXES or rest.isdigit()):
                        match = (r, brand, 'affix')
                        scammy = True
                    elif (kwlen >= 6 and kw not in COMMON_WORD_KEYWORDS and len(r) >= kwlen - (1 if kwlen >= 8 else 0)
                          and _dl(t, kw, 1) == 1):
                        match = (r, brand, 'typo')
                    if match:
                        break
                if match:
                    break
            if match:
                r, brand, how = match
                kw_common = skeleton(r) in COMMON_WORD_KEYWORDS
                conf = 0.84 if how == 'typo' else 0.86
                if kw_common and not scammy:
                    conf = 0.45  # e.g. apple-orchard.org: brand word, but nothing phishing-like around it
                ev = (f'uses the brand name "{r}" ({brand.name}) but the domain belongs to {reg_uni}' if how != 'typo'
                      else f'"{r}" is a misspelling of the brand {brand.name}, inside the unrelated domain {reg_uni}')
                if kw_common and not scammy:
                    ev += ' (common word; weak signal on its own)'
                found.append(Finding('combosquat', brand.domains[0], brand.name, conf, ev))
        found.sort(key=lambda f: -f.confidence)
        v.findings = found
        return v

    def claimed_brands(self, text: str) -> list[Brand]:
        """Brands a message *claims* to be from (name or keyword mentioned in text)."""
        t = skeleton(text)
        out = []
        for b in self.brands:
            names = {skeleton(b.name.split(' /')[0])} | {skeleton(k) for k in b.keywords if len(k) >= 3}
            if any(re.search(rf'(?<![a-z]){re.escape(n)}(?![a-z])', t) for n in names):
                out.append(b)
        return out[:5]


@lru_cache(maxsize=1)
def get_brand_engine() -> BrandEngine:
    return BrandEngine()
