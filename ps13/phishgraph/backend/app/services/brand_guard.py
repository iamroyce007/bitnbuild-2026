"""Brand-claim guard: the one rule PhishGraph guarantees, independent of every model.

    A message that PRESENTS ITSELF AS a protected brand B, and is NOT from B's verified sender, and contains a link to
    ANY host that is not one of B's official domains (user-content hosts such as sites.google.com, forms.gle or
    *.github.io never count as official, since anyone can publish there), is never ALLOWed. It is at least FLAGged, and the report names
    B's official site so the person can go there directly instead.

"Presents itself as B" is deliberately narrow so ordinary mentions do not trip it:
  - B appears in the sender's display name, the subject, or the SMS sender ID; or
  - B appears in the body AND the message asks for an action phishing needs (credentials, OTP/PIN, KYC, payment,
    account unlock/suspension, password reset, UPI collect).
"Verified sender of B": the sender's domain is one of B's official domains with no SPF/DKIM/DMARC failure, or (SMS) the
registered DLT sender header matches B (metadata_engine's trust signals).

Why a rule and not a score: models give probabilities; this gives a property that holds for every input, and
tests/test_brand_guard.py checks it exhaustively for every protected brand. It covers the most common phishing
pattern (brand impersonation with a link); it cannot cover messages without a link or a brand claim, and it does
not claim to.
"""
from __future__ import annotations

import re

from .brand_engine import get_brand_engine
from .url_features import FREE_HOSTING

ACTION_INTENTS = {'credential_request', 'otp_request', 'identity_verification', 'payment_request', 'account_suspension',
                  'password_reset', 'upi_collect', 'invoice_fraud'}


def _names(brands) -> dict[str, object]:
    return {b.name: b for b in brands}


def family(b) -> str:
    """Brand family: the first word of the name ("HDFC Bank" / "HDFC ERGO" -> "hdfc", "Google" / "Google Pay" -> "google").
    A domain officially owned by any member counts as official for the whole family; attackers cannot own those domains."""
    return b.name.split(' /')[0].split()[0].lower()


def check(pm, nlp, url_results, meta) -> list[dict]:
    """Violations of the rule: [{brand, official, hosts}] (empty = the rule does not apply)."""
    if not url_results:
        return []
    be = get_brand_engine()
    identity = ' '.join(x for x in (pm.sender_name, pm.subject, pm.sender if pm.channel != 'email' else '') if x)
    claimed = _names(be.claimed_brands(identity)) if identity.strip() else {}
    intents = {i.id for i in (nlp.intents if nlp else [])}
    if intents & ACTION_INTENTS:
        claimed |= _names(be.claimed_brands(pm.text[:3000]))
    if not claimed:
        return []

    auth_failed = any((pm.auth or {}).get(m) in ('fail', 'softfail', 'permerror') for m in ('spf', 'dkim', 'dmarc'))
    sender_brand = be.official_brand(pm.sender_domain) if pm.sender_domain else None
    dlt_verified = pm.channel != 'email' and any('registered SMS sender header' in t for t in (meta.trust or []))

    out, done = [], set()
    for name, b in claimed.items():
        fam = family(b)
        if fam in done:
            continue  # one entry per family ("Google" and "Google Pay" are the same owner)
        done.add(fam)
        if (sender_brand is not None and family(sender_brand) == fam and not auth_failed) or dlt_verified:
            continue  # genuinely from the brand (family)
        hosts = []
        for u in url_results:
            h = (u.parsed.host or '').lower()
            if not h:
                continue
            ob = be.official_brand(h)
            # user-content hosts (sites.google.com, forms.gle, *.github.io ...) are never "official": anyone can publish there
            user_content = any(h == f or h.endswith('.' + f) for f in FREE_HOSTING) or h in ('docs.google.com', 'drive.google.com')
            if ob is None or family(ob) != fam or user_content:
                hosts.append(h)
        if hosts:
            official = next((d for d in b.domains if not re.search(r'\d', d)), b.domains[0]) if b.domains else ''
            out.append({'brand': name, 'official': official, 'hosts': list(dict.fromkeys(hosts))[:4]})
    return out
