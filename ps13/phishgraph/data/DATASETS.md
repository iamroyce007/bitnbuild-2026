# Datasets

Downloaded by `scripts/download_datasets.py`, which also writes `data/DATASETS.lock.json` (URL, licence, download date, SHA-256, size, row / label counts). Raw files live in `data/raw/` and are not committed.

## Reference data (needed at runtime)
| Name | Source | Licence | Used for |
|---|---|---|---|
| Tranco top 1M | https://tranco-list.eu | free for research & commercial use | protected look-alike targets (top 10k) and "established" allowlist (top 100k) |
| Public Suffix List | https://github.com/publicsuffix/list | MPL-2.0 | registrable-domain extraction (`co.in`, `github.io`, `web.app` …) |
| Unicode confusables | https://www.unicode.org/Public/security/latest/confusables.txt | Unicode License v3 | UTS #39 skeletons for homograph detection |
| all-MiniLM-L6-v2 | https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2 | Apache-2.0 | semantic stage of the NLP engine (optional) |

## Training data
| Name | Source | Licence | Size | Notes |
|---|---|---|---|---|
| ealvaradob/phishing-dataset `urls.json` | Hugging Face | Apache-2.0 | 835,697 URLs (444,933 legit / 390,764 phishing) | URLs without scheme |
| PhiUSIIL Phishing URL Dataset | UCI ML Repository #967 | CC BY 4.0 | 235,795 URLs | **label 1 = legitimate** (inverted on load); legitimate URLs are mostly bare homepages, a strong dataset artifact |
| ealvaradob/phishing-dataset `texts.json` | Hugging Face | Apache-2.0 | 20,137 texts (emails + SMS) | legitimate e-mail is largely Enron corporate mail; SMS spam is labelled as phishing |
| zefang-liu/phishing-email-dataset | Hugging Face | LGPL-3.0 | 18,650 emails | **fully contained in `texts.json`** after normalisation; contributes no independent samples |

## Processing
- URLs: scheme and `www.` stripped before n-gram features (both are source artifacts); exact duplicates and conflicting labels removed → 1,025,138 unique URLs; 420,000 sampled for training and evaluation.
- Texts: exact duplicates across sources removed (normalised text hash) → 19,855 messages; corpus-signature tokens (e.g. `enron`, `ect`, `hou`) dropped by the tokenizer.
- Splits reported: random stratified, domain-grouped (GroupShuffleSplit by registrable domain), cross-source (URL), cross-channel (short SMS-like vs long email-like texts).

## Live intelligence (not training data)
OpenPhish community feed, PhishTank (app key), URLhaus (auth key): ingested into the local IOC store on a schedule. Analyst-confirmed indicators and false positives from the feedback loop accumulate in `data/processed/*.jsonl` for approval-based retraining.

## Demo data
`data/demo/demo_dataset.json`: 12 legitimate and 15 phishing messages, 14 fictional domains with infrastructure on RFC 5737 IPs / RFC 5398 ASNs, 6 demo feed IOCs. Labelled `DEMO DATA` wherever it appears; never mixed with real intelligence.
