"""'Investigate unknown URL': full chain for a single URL (normalise -> SSRF guard -> DNS -> RDAP -> TLS -> IP -> ASN ->
threat intel -> graph traversal -> brand -> campaign similarity -> risk). Runs as a background job (202 Accepted)."""
from __future__ import annotations

from ..utils.url_utils import parse_url, ssrf_block_reason
from .email_parser import ParsedMessage
from .url_extractor import ExtractedURL


async def investigate(url: str, demo: bool = False) -> dict:
    from ..config import get_settings
    from .pipeline import analyze
    p = parse_url(url)
    if p is None:
        return {'error': 'not a valid URL'}
    if p.host:
        why = ssrf_block_reason(p.host)
        if why and not get_settings().allow_private_targets:
            return {'error': f'refused: {why} (SSRF protection)', 'url': url}
    pm = ParsedMessage(channel='url', text='', urls=[ExtractedURL(p, ['investigation'])])
    return await analyze(pm, source='investigation', deep=True, demo=demo, kind='investigation')
