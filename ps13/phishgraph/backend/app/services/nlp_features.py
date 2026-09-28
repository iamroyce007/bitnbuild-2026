"""Tokenisation shared by NLP training and inference."""
from __future__ import annotations

import re
import unicodedata

RE_URL = re.compile(r'(?:https?://|www\.)\S+')
RE_EMAIL = re.compile(r'[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}')
RE_MONEY = re.compile(r'(?:₹|rs\.?|inr|\$|usd|£|€)\s?\d[\d,]*(?:\.\d+)?')
RE_NUM = re.compile(r'\d+')
RE_TOK = re.compile(r'[a-zऀ-ॿ஀-௿]+')
# tokens that identify a *corpus* rather than phishing behaviour (Enron signatures etc.) are dropped
ARTIFACTS = {'enron', 'ect', 'hou', 'vince', 'kaminski', 'louise', 'kitchen', 'hpl', 'daren', 'farmer', 'meter', 'nom', 'ena', 'cc', 'subject', 'forwarded', 'escapenumber', 'escapelong'}


def tokens(s: str) -> list[str]:
    s = unicodedata.normalize('NFKC', s).lower()
    s = RE_URL.sub(' zzurl ', s)
    s = RE_EMAIL.sub(' zzemail ', s)
    s = RE_MONEY.sub(' zzmoney ', s)
    s = RE_NUM.sub(' zznum ', s)
    return [t for t in RE_TOK.findall(s) if 2 <= len(t) <= 24 and t not in ARTIFACTS]


def word_features(s: str) -> list[str]:
    t = tokens(s)[:800]
    return ['w:' + x for x in t] + ['b:' + a + '_' + b for a, b in zip(t, t[1:])]
