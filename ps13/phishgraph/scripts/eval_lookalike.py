"""Measure the look-alike engine instead of claiming it works.

1. False-alarm rate on real, mostly-legitimate domains that are NOT auto-trusted:
   Tranco ranks 100,001-150,000 (outside the 'established' allowlist, so the engine must judge them).
2. Detection rate on generated attack domains (dnstwist-style permutations of protected brands),
   excluding any permutation that actually exists in the Tranco top 1M (those may be legitimate or defensive).
3. Zero false alarms on the brands' own official domains and their subdomains.
Writes data/processed/lookalike_eval.json.
"""
from __future__ import annotations

import csv
import json
import random
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from app.services.brand_engine import get_brand_engine  # noqa: E402
from app.utils.url_utils import split_host  # noqa: E402

random.seed(13)
E = get_brand_engine()
ROOT = Path(__file__).resolve().parents[1]

# ---------- 1. false alarms on real domains ----------
real = []
with open(ROOT / 'data/raw/top-1m.csv') as f:
    for row in csv.reader(f):
        r = int(row[0])
        if 100_000 < r <= 150_000:
            real.append(row[1])
t = time.time()
flag_kinds = Counter()
flagged = []
for d in real:
    v = E.analyze(d)
    if v.findings and v.score >= 0.7:
        flag_kinds[v.findings[0].kind] += 1
        flagged.append((d, v.findings[0].kind, v.findings[0].target_domain))
dt = time.time() - t
fp_rate = len(flagged) / len(real)
print(f'[real domains] {len(real)} domains, strong look-alike flags: {len(flagged)} ({fp_rate:.2%}), {len(real) / dt:.0f} domains/s')
print('   by kind:', dict(flag_kinds))
print('   sample flagged (manually review; many are genuine typosquats in the wild):', flagged[:12])

# ---------- 2. detection of generated attacks ----------
HOMO = {'o': ['0', 'о'], 'a': ['а'], 'e': ['е', '3'], 'i': ['1', 'і'], 'l': ['1', 'I'], 'c': ['с'], 'p': ['р'], 'm': ['rn'], 's': ['5'], 'g': ['9']}
KEYB = {'a': 'qs', 'b': 'vn', 'c': 'xv', 'd': 'sf', 'e': 'wr', 'f': 'dg', 'g': 'fh', 'h': 'gj', 'i': 'uo', 'j': 'hk', 'k': 'jl', 'l': 'k', 'm': 'n', 'n': 'bm', 'o': 'ip', 'p': 'o', 'q': 'w', 'r': 'et', 's': 'ad', 't': 'ry', 'u': 'yi', 'v': 'cb', 'w': 'qe', 'x': 'zc', 'y': 'tu', 'z': 'x'}
AFFIX = ['secure', 'login', 'verify', 'account', 'support', 'update', 'kyc', 'billing', 'help']
TLDS = ['xyz', 'online', 'top', 'info', 'site', 'co', 'net', 'live']
tranco_all = set(E.rank)


def perms(label: str, suf: str) -> list[tuple[str, str]]:
    out = []
    i = random.randrange(len(label))
    for pos, ch in enumerate(label):
        if ch in HOMO:
            out.append(('homoglyph', label[:pos] + random.choice(HOMO[ch]) + label[pos + 1:] + '.' + suf))
            break
    out.append(('omission', label[:i] + label[i + 1:] + '.' + suf))
    out.append(('repetition', label[:i] + label[i] + label[i:] + '.' + suf))
    if i < len(label) - 1:
        out.append(('transposition', label[:i] + label[i + 1] + label[i] + label[i + 2:] + '.' + suf))
    if label[i] in KEYB:
        out.append(('keyboard', label[:i] + random.choice(KEYB[label[i]]) + label[i + 1:] + '.' + suf))
    out.append(('combosquat', f'{label}-{random.choice(AFFIX)}.{random.choice(TLDS)}'))
    out.append(('subdomain', f'{label}.{suf}.{random.choice(AFFIX)}-{random.randint(10, 99)}.{random.choice(TLDS)}'))
    return out


targets = []
for b in E.brands:
    for d in b.domains[:2]:
        sub, reg, suf = split_host(d)
        lab = reg[: -len(suf) - 1] if suf and reg != suf else reg
        if len(lab) >= 5:
            targets.append((lab, suf, True))
for lab, (dom, brand, pr) in list(E.protected.items()):
    if brand is None and pr <= 2000 and len(lab) >= 6:
        targets.append((lab, split_host(dom)[2], False))
attacks = []
for lab, suf, curated in targets:
    for kind, d in perms(lab, suf):
        reg = split_host(d.split('/')[0])[1]
        if reg in tranco_all:
            continue  # exists in the wild: could be legitimate, excluded from recall
        attacks.append((kind, d, curated))
hit = Counter()
weak = Counter()
tot = Counter()
misses = []
for kind, d, curated in attacks:
    if kind == 'combosquat' and not curated:
        continue  # combosquat detection is intentionally limited to curated brands
    grp = ('brand ' if curated else 'popular ') + kind
    tot[grp] += 1
    v = E.analyze(d)
    if v.findings and v.score >= 0.7:
        hit[grp] += 1
    elif v.findings:
        weak[grp] += 1
    elif len(misses) < 15:
        misses.append((grp, d))
total = sum(tot.values())
cur_tot = sum(v for k, v in tot.items() if k.startswith('brand'))
cur_hit = sum(v for k, v in hit.items() if k.startswith('brand'))
recall = cur_hit / cur_tot
any_rate = (sum(hit.values()) + sum(weak.values())) / total
print(f'[generated attacks] {total} look-alikes of {len(targets)} protected names')
print(f'   curated brands, strong flag: {cur_hit}/{cur_tot} ({recall:.2%});  any signal (strong or weak), all targets: {any_rate:.2%}')
for k in sorted(tot):
    print(f'   {k:24s} strong {hit[k]:5d}  weak {weak[k]:5d}  / {tot[k]:<5d}')
print('   sample misses:', misses)

# ---------- 3. official domains must never be flagged ----------
official_fp = []
for b in E.brands:
    for d in b.domains:
        for h in (d, 'www.' + d, 'login.' + d, 'secure.accounts.' + d):
            if E.analyze(h).findings:
                official_fp.append(h)
print(f'[official domains] {sum(len(b.domains) * 4 for b in E.brands)} hosts checked, flagged: {len(official_fp)}', official_fp[:5])

out = {
    'real_domains': {'source': 'Tranco ranks 100,001-150,000', 'n': len(real), 'flagged': len(flagged), 'rate': round(fp_rate, 5), 'by_kind': dict(flag_kinds), 'sample': flagged[:40]},
    'generated_attacks': {'n': total, 'curated_strong_recall': round(recall, 5), 'any_signal_rate': round(any_rate, 5), 'by_group': {k: {'strong': hit[k], 'weak': weak[k], 'n': tot[k]} for k in tot}},
    'official_domains': {'flagged': official_fp},
    'throughput_domains_per_s': round(len(real) / dt),
}
(ROOT / 'data/processed').mkdir(parents=True, exist_ok=True)
(ROOT / 'data/processed/lookalike_eval.json').write_text(json.dumps(out, indent=1, ensure_ascii=False))

from app.services import validation_log  # noqa: E402
validation_log.append('lookalike', {'real_domains_n': len(real), 'real_flag_rate': round(fp_rate, 5), 'attacks_n': total,
                                    'curated_strong_recall': round(recall, 5), 'any_signal_rate': round(any_rate, 5),
                                    'official_flagged': len(official_fp)}, out, target='brand engine')
