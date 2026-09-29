"""URL engine: calibrated ML probability + deterministic lexical rules + brand/look-alike verdict.

Explanations for the ML part are exact for the linear char-n-gram model (coefficient x feature value)
and rule-based for everything else, so no reason is ever inferred after the fact.
"""
from __future__ import annotations

import re

import logging
from dataclasses import dataclass, field
from functools import lru_cache

import joblib
import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer

from ..config import get_settings
from ..utils.url_utils import ParsedURL, parse_url
from .brand_engine import DomainVerdict, get_brand_engine
from .url_features import FREE_HOSTING, FEATURE_NAMES, char_ngrams, url_features

log = logging.getLogger(__name__)


@dataclass
class URLResult:
    parsed: ParsedURL
    score: float  # 0-100 combined URL risk (ML + rules + brand)
    ml_probability: float | None
    brand: DomainVerdict | None
    rules: list[dict] = field(default_factory=list)  # {id, label, weight}
    features: dict = field(default_factory=dict)
    top_ngrams: list[tuple[str, float]] = field(default_factory=list)
    trusted: bool = False
    sources: list[str] = field(default_factory=list)
    deceptive_text: str | None = None


class URLEngine:
    def __init__(self) -> None:
        path = get_settings().models_dir / 'url' / 'url_model.joblib'
        self.m = joblib.load(path) if path.exists() else None
        if self.m is None:
            log.warning('URL model missing at %s; URL engine runs rules + brand only', path)
            self.hv = None
        else:
            self.hv = HashingVectorizer(analyzer=char_ngrams, n_features=self.m['n_features'], alternate_sign=False, norm='l2')
            self.single = HashingVectorizer(analyzer=lambda s: [s], n_features=self.m['n_features'], alternate_sign=False, norm=None)
        self.brands = get_brand_engine()

    def predict(self, urls: list[str]) -> np.ndarray:
        if self.m is None:
            return np.full(len(urls), np.nan)
        X = self.hv.transform(urls)
        p_lr = self.m['lr'].predict_proba(X)[:, 1]
        F = np.array([[url_features(u)[k] for k in FEATURE_NAMES] for u in urls], dtype=np.float32)
        p_hgb = self.m['hgb'].predict_proba(F)[:, 1]
        return self.m['iso'].predict((p_lr + p_hgb) / 2)

    def _ngram_reasons(self, url: str) -> list[tuple[str, float]]:
        grams = list(dict.fromkeys(char_ngrams(url)))
        X = self.hv.transform([url])
        cols = self.single.transform(grams)
        names = {cols[i].indices[0]: g for i, g in enumerate(grams) if len(cols[i].indices)}
        coef = self.m['lr'].coef_[0]
        contrib = sorted(((names[j], float(coef[j] * v)) for j, v in zip(X.indices, X.data) if j in names), key=lambda kv: -kv[1])
        out, used = [], set()
        for g, c in contrib:
            core = g.strip('^$')
            if c <= 0 or any(core in u or u in core for u in used):
                continue
            used.add(core)
            out.append((core, round(c, 3)))
            if len(out) == 5:
                break
        return out

    def analyze(self, url: str | ParsedURL, sources: list[str] | None = None, deceptive_text: str | None = None) -> URLResult | None:
        p = url if isinstance(url, ParsedURL) else parse_url(url)
        if p is None:
            return None
        rules: list[dict] = []

        def rule(i: str, label: str, w: float) -> None:
            rules.append({'id': i, 'label': label, 'weight': w})

        if p.scheme in ('javascript', 'data'):
            rule('script_url', f'Link executes code ({p.scheme}:) instead of opening a page', 0.7)
            return URLResult(p, 70.0, None, None, rules, sources=sources or [])
        f = url_features(p.normalized)
        bv = self.brands.analyze(p.host) if p.host else None
        if bv and bv.findings:
            fd = bv.findings[0]
            rule(f'brand_{fd.kind}', fd.evidence, fd.confidence)
        if f['is_ip']:
            rule('ip_host', 'Uses a raw IP address instead of a domain name', 0.35)
        if f['has_at']:
            rule('userinfo', 'Contains "@" before the host: the browser ignores everything before it', 0.4)
        if f['is_punycode']:
            rule('punycode', f'Internationalised domain that displays as "{p.host_unicode}"', 0.25)
        if bv and bv.mixed_script:
            rule('mixed_script', f'Domain mixes alphabets ({", ".join(bv.scripts)})', 0.45)
        if f['is_shortener']:
            rule('shortener', f'Link shortener ({p.registrable}) hides the real destination', 0.15)
        if f['free_hosting']:
            rule('free_hosting', f'Hosted on a free/throw-away platform ({p.registrable})', 0.18)
            # a brand named on a site anyone can publish to (online-secured.github.io/Wells, xfinitymail01.weebly.com):
            # real brands do not serve sign-in pages from someone's GitHub Pages / Weebly / Firebase site
            words = re.sub(r'[/_\-.?=&#+]+', ' ', f'{p.subdomain} {p.path} {p.query}')
            platform = self.brands.official_brand(p.registrable or p.host)
            named = [b for b in self.brands.claimed_brands(words)
                     if not platform or b.name.split(' /')[0].split()[0].lower() != platform.name.split(' /')[0].split()[0].lower()]
            if named:
                rule('brand_on_user_content', f'Names {named[0].name} on {p.host}, a site anyone can publish to; '
                     f'{named[0].name} does not host its pages there', 0.62)
        if f['suspicious_tld']:
            rule('suspicious_tld', f'.{p.host.rsplit(".", 1)[-1]} domains are cheap and heavily abused', 0.12)
        if f['n_subdomains'] >= 4:
            rule('deep_subdomains', f'Unusually deep subdomain chain ({p.subdomain})', 0.15)
        if f['has_port']:
            rule('port', f'Non-standard port :{p.port}', 0.12)
        if f['exec_ext']:
            rule('executable', f'Downloads an executable/installer ({p.path.rsplit(".", 1)[-1]})', 0.45)
        if f['n_keywords'] >= 2:
            rule('cred_keywords', 'URL contains several login/verification keywords', 0.1)
        if f['n_susp_params']:
            rule('redirect_param', 'Query string carries a redirect/continue target or your email address', 0.08)
        if p.scheme == 'http' and f['n_keywords']:
            rule('http_sensitive', 'Asks for sensitive action over unencrypted http://', 0.1)
        if f['random_path']:
            rule('random_path', 'High-entropy random-looking path (typical of kit-generated phishing pages)', 0.06)
        if deceptive_text:
            rule('deceptive_link_text', deceptive_text, 0.55)
        if p.unwrapped:
            rule('wrapped', f'Tracking/safe-link wrapper around {len(p.unwrapped)} inner URL(s)', 0.04)

        prob = None
        top: list[tuple[str, float]] = []
        if self.m is not None and p.host:
            prob = float(self.predict([p.normalized])[0])
            top = self._ngram_reasons(p.normalized)
        # a user-content host never inherits its platform's reputation: *.github.io is not GitHub, *.weebly.com is not Weebly
        root = next((h for h in FREE_HOSTING if p.host == h or p.host.endswith('.' + h)), None)
        user_content = bool(root) and p.host not in (root, 'www.' + root)
        trusted = (bool(bv and (bv.official_brand or bv.established)) and not user_content
                   and not any(r['id'] in ('userinfo', 'executable', 'deceptive_link_text') for r in rules))
        rule_risk = 1.0
        for r in rules:
            rule_risk *= 1 - r['weight']
        rule_risk = 1 - rule_risk
        ml = prob if prob is not None else 0.0
        # URL ML generalises poorly across data sources (cross-source F1 ~0.6), so on its own it is only
        # moderate evidence; corroborating rules or brand findings let it count fully.
        # on a user-content host "free hosting" is a fact about the platform, not evidence against this page:
        # only concrete rules (brand named, look-alike, sign-in keywords ...) corroborate the model there
        concrete = [r for r in rules if r['id'] != 'free_hosting'] if user_content else rules
        ml_weight = 0.8 if concrete else 0.45
        combined = 1 - (1 - rule_risk) * (1 - ml_weight * ml)
        if user_content and not concrete:
            # measured trade-off (scripts/real_world_check.py): phishing on free hosting is very common, so the model may
            # still FLAG such a page for verification, but never quarantine/block it without concrete evidence
            combined = min(combined, 0.55)
        if trusted:
            # an official or top-100k site: ML n-gram noise alone must not flag it; hard rules still can
            combined = min(combined, max(rule_risk * 0.6, 0.02))
        return URLResult(p, round(100 * combined, 1), prob, bv, rules, f, top, trusted, sources or [], deceptive_text)


@lru_cache(maxsize=1)
def get_url_engine() -> URLEngine:
    return URLEngine()
