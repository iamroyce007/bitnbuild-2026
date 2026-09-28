"""ThreatIntelOrchestrator: cache -> choose providers per IOC type -> query concurrently -> normalise ->
source-confidence-weighted score. One provider failing never breaks detection; unavailable sources are
reported as such and their weight is redistributed by the risk engine."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from ..connectors.base import TIResult
from ..connectors.providers import ALL


@dataclass
class TISummary:
    score: float  # 0-100 (meaningful only if available)
    available: bool  # at least one source returned a real answer
    results: list[TIResult] = field(default_factory=list)
    hits: list[TIResult] = field(default_factory=list)  # malicious/suspicious answers
    clean_votes: int = 0
    sources_ok: list[str] = field(default_factory=list)
    sources_unavailable: list[str] = field(default_factory=list)


class ThreatIntelOrchestrator:
    def __init__(self) -> None:
        self.providers = [cls() for cls in ALL]

    def health(self) -> list[dict]:
        return [p.health() for p in self.providers]

    async def lookup_many(self, iocs: list[tuple[str, str]], max_iocs: int = 12) -> TISummary:
        iocs = list(dict.fromkeys(iocs))[:max_iocs]
        tasks = [p.lookup(t, v) for t, v in iocs for p in self.providers if t in p.supports]
        results: list[TIResult] = list(await asyncio.gather(*tasks)) if tasks else []
        ok = [r for r in results if r.status == 'ok']
        external_ok = [r for r in ok if r.source != 'local_intel']
        hits = [r for r in ok if r.verdict in ('malicious', 'suspicious')]
        # noisy-OR over sources, each weighted by its own confidence
        acc = 1.0
        for r in hits:
            acc *= 1 - (r.risk / 100) * r.confidence
        score = 100 * (1 - acc)
        clean = sum(1 for r in external_ok if r.verdict == 'clean')
        # a local feed with no match is absence of evidence, not evidence of safety: only a hit or a real
        # external answer makes threat intelligence "available" for fusion
        available = bool(hits) or bool(external_ok)
        return TISummary(score=round(score, 1), available=available, results=results, hits=hits, clean_votes=clean,
                         sources_ok=sorted({r.source for r in ok}),
                         sources_unavailable=sorted({r.source for r in results if r.status not in ('ok', 'not_supported')}))


_orch: ThreatIntelOrchestrator | None = None


def get_ti() -> ThreatIntelOrchestrator:
    global _orch
    if _orch is None:
        _orch = ThreatIntelOrchestrator()
    return _orch
