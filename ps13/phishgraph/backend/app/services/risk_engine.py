"""Risk fusion + decision.

final = sum(w_i * score_i) over the sources that actually produced evidence, with weights renormalised
when a source is unavailable (e.g. no threat-intel keys configured) so a missing source never counts as "safe".
Hard evidence can raise the floor (exact known-bad IOC, homograph of a protected brand) and trusted
destinations can lower the ceiling; each override is listed in the output. Weights and thresholds are configurable.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..config import get_settings


@dataclass
class Fusion:
    final: float
    decision: str
    scores: dict[str, float | None]
    weights_used: dict[str, float]
    overrides: list[str] = field(default_factory=list)
    conflicting_intelligence: bool = False
    conflict_detail: str | None = None
    unavailable: list[str] = field(default_factory=list)


def decide(score: float) -> str:
    s = get_settings()
    if score >= s.t_block:
        return 'BLOCK'
    if score >= s.t_quarantine:
        return 'QUARANTINE'
    if score >= s.t_flag:
        return 'FLAG'
    return 'ALLOW'


def fuse(nlp: float | None, url: float | None, ti: float | None, graph: float | None, brand: float | None, meta: float | None,
         hard_known_bad: bool = False, strong_brand: bool = False, all_urls_trusted: bool = False, ti_clean_votes: int = 0,
         evasion: bool = False) -> Fusion:
    st = get_settings()
    base = {'nlp': st.w_nlp, 'url': st.w_url, 'threat_intelligence': st.w_ti, 'graph': st.w_graph, 'brand': st.w_brand, 'metadata': st.w_meta}
    scores = {'nlp': nlp, 'url': url, 'threat_intelligence': ti, 'graph': graph, 'brand': brand, 'metadata': meta}
    avail = {k: v for k, v in scores.items() if v is not None}
    wsum = sum(base[k] for k in avail) or 1.0
    weights = {k: round(base[k] / wsum, 4) for k in avail}
    linear = sum(weights[k] * avail[k] for k in avail)
    # the strongest single independent signal should never be diluted below ~85% of itself
    peak = max(avail.values(), default=0.0)
    final = max(linear, 0.85 * peak if peak >= 85 else linear)
    overrides = []
    if hard_known_bad:
        final = max(final, 92.0)
        overrides.append('exact match with a known-malicious indicator (floor 92)')
    if strong_brand and (nlp or 0) >= 40:
        final = max(final, 85.0)
        overrides.append('look-alike of a protected brand plus phishing language (floor 85)')
    if evasion and final >= 30:
        final = min(100.0, final + 8)
        overrides.append('filter-evasion techniques present (+8)')
    if all_urls_trusted and not hard_known_bad and not strong_brand and (meta or 0) < 40:
        cap = 45.0 if (nlp or 0) >= 70 else 30.0
        if final > cap:
            final = cap
            overrides.append(f'every link goes to an official/established domain (cap {int(cap)})')
    conflict, detail = False, None
    if ti is not None and ti_clean_votes and (graph or 0) >= 60:
        conflict, detail = True, 'threat-intel sources report the indicators as clean, but the graph links them to suspicious infrastructure'
    elif ti is not None and ti >= 70 and (nlp or 0) < 20 and (url or 0) < 30:
        conflict, detail = True, 'threat intelligence flags an indicator that content and URL analysis consider benign'
    final = round(min(100.0, max(0.0, final)), 1)
    return Fusion(final, decide(final), {k: (round(v, 1) if v is not None else None) for k, v in scores.items()}, weights, overrides, conflict, detail,
                  [k for k, v in scores.items() if v is None])
