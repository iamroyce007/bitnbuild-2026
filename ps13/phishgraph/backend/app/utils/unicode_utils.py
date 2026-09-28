"""Unicode security analysis (UTS #39): confusable skeletons, script mixing, punycode.

The skeleton is computed from the official Unicode confusables.txt (thousands of mappings),
so 'g00gle', 'gооgle' (Cyrillic o) and 'googIe' (capital I) all reduce to the same skeleton
as 'google'. Two strings are visually confusable iff their skeletons are equal.
"""
from __future__ import annotations

import unicodedata
from functools import lru_cache

import idna

from ..config import get_settings


@lru_cache(maxsize=1)
def _confusables() -> dict[str, str]:
    path = get_settings().data_dir / 'raw' / 'confusables.txt'
    table: dict[str, str] = {}
    with open(path, encoding='utf-8-sig') as f:
        for line in f:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(';')]
            if len(parts) < 2:
                continue
            src = ''.join(chr(int(h, 16)) for h in parts[0].split())
            dst = ''.join(chr(int(h, 16)) for h in parts[1].split())
            if len(src) == 1:
                table[src] = dst
    return table


def skeleton(s: str) -> str:
    """UTS #39 skeleton, then case-folded, so comparisons are visual rather than exact."""
    table = _confusables()
    s = unicodedata.normalize('NFD', s)
    s = ''.join(table.get(ch, ch) for ch in s)
    s = unicodedata.normalize('NFD', s)
    # case folding happens after mapping so that 'I' (capital i) and 'l' collapse too
    s = ''.join(table.get(ch, ch) for ch in s.casefold())
    return unicodedata.normalize('NFD', s)


def script_of(ch: str) -> str:
    if ch.isascii():
        return 'LATIN' if ch.isalpha() else 'COMMON'
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return 'UNKNOWN'
    first = name.split(' ')[0]
    if first in ('LATIN', 'CYRILLIC', 'GREEK', 'ARMENIAN', 'CHEROKEE', 'DEVANAGARI', 'TAMIL', 'ARABIC', 'HEBREW', 'CJK', 'HIRAGANA', 'KATAKANA', 'HANGUL', 'THAI', 'GEORGIAN'):
        return first
    if first in ('FULLWIDTH', 'MATHEMATICAL', 'DOUBLE-STRUCK', 'SCRIPT', 'SMALL', 'MODIFIER', 'SUBSCRIPT', 'SUPERSCRIPT', 'CIRCLED', 'PARENTHESIZED'):
        return 'COMPAT'
    if not ch.isalpha():
        return 'COMMON'
    return first


def scripts_in(label: str) -> set[str]:
    return {script_of(c) for c in label if script_of(c) not in ('COMMON',)}


def is_mixed_script(label: str) -> bool:
    sc = scripts_in(label)
    return len(sc) > 1 or 'COMPAT' in sc


def to_unicode(host: str) -> str:
    """Decode xn-- labels for display and analysis; never raises."""
    out = []
    for label in host.split('.'):
        if label.lower().startswith('xn--'):
            try:
                out.append(idna.decode(label))
                continue
            except Exception:
                try:
                    out.append(label.encode('ascii').decode('idna'))
                    continue
                except Exception:
                    pass
        out.append(label)
    return '.'.join(out)


def to_ascii(host: str) -> str:
    try:
        return host.encode('idna').decode('ascii').lower()
    except Exception:
        try:
            return idna.encode(host, uts46=True).decode('ascii').lower()
        except Exception:
            return host.lower()


ZERO_WIDTH = {'​', '‌', '‍', '‎', '‏', '⁠', '⁡', '⁢', '⁣', '⁤', '﻿', '­', '͏', '᠎'}


def strip_invisible(s: str) -> tuple[str, int]:
    n = sum(1 for c in s if c in ZERO_WIDTH)
    return (''.join(c for c in s if c not in ZERO_WIDTH), n) if n else (s, 0)
