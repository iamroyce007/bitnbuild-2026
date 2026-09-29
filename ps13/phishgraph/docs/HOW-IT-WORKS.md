# PhishGraph: how it works

A detailed walkthrough for judges, reviewers and new contributors. Every number here is measured and reproducible (see
"Evidence" at the end); nothing is estimated.

## 1. The problem and the idea

Phishing reaches people as SMS, WhatsApp messages and emails. It moves fast: most phishing domains are used for hours
before any blocklist lists them. Tools that only ask "is this link on a blacklist?" or "does a classifier think it looks
bad?" miss those new domains.

PhishGraph asks a third question: **who else is using this infrastructure?** A brand-new domain that no feed has seen can
still sit on the same IP address, TLS certificate, nameserver or hosting platform as known-bad sites, or imitate the
same brand. PhishGraph builds that picture as a graph and shows the exact path in the verdict.

## 2. What happens to one message, step by step

Take the SMS: *"VM-SBIINB: Dear SBI customer, your YONO account will be blocked today. Update KYC at
sbi-kyc-update.site/kyc. Share OTP with our officer."*

1. **Get the message in.** Paste it, or upload a screenshot. For a screenshot, OCR runs inside the browser, so the image
   never leaves the device. `screenshot_extractor.py` then removes phone chrome (clock, battery, "Delivered"), repairs
   OCR-broken links, reads the layout (sender `VM-SBIINB`, message body) and lists every entity: the link, the DLT sender
   header, the brand SBI, the OTP request and the deadline.
2. **Undo evasion.** `text_normalizer.py` removes zero-width characters, converts Cyrillic look-alike letters, re-fangs
   `hxxp` and `[.]`, joins s p a c e d letters and decodes base64 links. Each trick it finds counts as evidence.
3. **Find every link**, including bare domains, buttons, form actions and unwrapped safe-link redirects (`url_extractor.py`).
4. **Six engines score it in parallel:**

   | Engine | What it looks at | For this SMS |
   |---|---|---|
   | Language (NLP) | a TF-IDF model, a MiniLM embedding model, and 20 scam intents in English, Hindi, Tamil, Hinglish and Tanglish | urgency, account suspension, KYC, OTP request |
   | URL model | a character n-gram model plus 37 lexical features, calibrated | a phishing-shaped URL |
   | Brand / look-alike | 95 curated brands and the Tranco top 10,000, Unicode confusables, the Public Suffix List | "sbi" used in someone else's domain |
   | Sender | SPF/DKIM/DMARC, display-name spoofing, Indian DLT sender headers, reply-to mismatch | registered header `VM-SBIINB` |
   | Threat intelligence | a local store of ~152,000 live indicators (OpenPhish, URLhaus, CERT Polska, Phishing Army) plus VirusTotal and others when keys are set | a known-bad match if listed |
   | Infrastructure graph | shared IP, certificate, nameserver, ASN, hosting platform and campaigns | links to known-bad neighbours |

5. **Fusion** (`risk_engine.py`) combines them:
   - Weights are **renormalised over the sources that answered**. A source with no answer is excluded, never counted as safe.
   - Hard evidence raises a floor: an exact known-bad indicator floors the score at 92; a strong look-alike plus scam
     language floors it at 85.
   - **Corroboration rule:** no single model can quarantine. QUARANTINE or BLOCK needs at least two independent evidence
     families, or one hard indicator.
   - A verified sender (the brand's own domain, or its registered SMS header) lowers the score.
   - **The brand guarantee** (section 3) is applied last.
   - Thresholds: ALLOW < 30 ≤ FLAG < 60 ≤ QUARANTINE < 85 ≤ BLOCK.
6. **Explain.** Every reason shown is copied from the engine that produced it, with its weight. No language model writes
   explanations. Sources that were unavailable say so, e.g. "n/a: weight redistributed, not counted as safe".
7. **Respond.** The response is simulated by default. BLOCK adds the indicators to the local feed, so the next message
   using this infrastructure is caught instantly.
8. **Learn.** An analyst's "confirm phishing" or "false positive" updates the feed and the graph and queues the example
   for the next training run.

## 3. The guarantee (the "100 %" part, stated honestly)

No detector can honestly promise to catch every phishing message, and PhishGraph does not claim to. It guarantees
**one rule** instead, which holds for every input:

> A message that presents itself as a protected brand B, is not from B's verified sender, and links anywhere outside B's
> official domains is **never ALLOWed**. It is at least FLAGged, and the person is told to go to B's official site
> themselves.

- It is a rule, not a probability, and it runs after everything else, so nothing can cancel it.
- Pages on a brand's own user-content hosts (`sites.google.com`, `forms.gle`, `*.github.io`) do not count as official,
  because anyone can publish there.
- It is **proven exhaustively**: `tests/test_brand_guard.py` checks all 95 brands. Each brand gets an email
  impersonation, a Google-Sites impersonation, an SMS impersonation, and a genuine message from its own domain that must
  not be touched: 380 cases plus regressions.
- Scope: it covers brand impersonation with a link, the most common pattern. Messages without a link or without a brand
  claim rely on the scored engines.

## 4. The threat graph, live

The graph fills from two directions:

- **Live feeds.** Every OpenPhish and URLhaus URL becomes a URL node on its domain. The domain is linked to the brand it
  impersonates and the hosting platform it abuses. Today that shows, for example, phishing clustered on `vercel.app`,
  `pages.dev` and `blogspot.com`, aimed at Microsoft, Meta, Apple and Chase.
- **Analyses.** Each message adds its links, domains, sender, IPs, ASNs, certificates, nameservers and its campaign.

Two safeguards keep the graph from inventing links:

- **Hub dampening.** Sharing a Cloudflare IP or a GoDaddy nameserver means almost nothing; sharing an uncommon nameserver
  or an identical certificate means a lot.
- **Feeds are lists, not infrastructure.** The graph never walks through a feed node, because two sites on the same list
  are not connected.

## 5. Accuracy: what was measured, including the uncomfortable parts

| What | Result |
|---|---|
| Look-alikes of the 95 brands (generated attacks) | 87.4 % strongly flagged |
| Real domains wrongly flagged as look-alikes (50,000 real sites) | 0.19 % |
| Official brand domains flagged | 0 of 928 |
| URL model alone vs **today's live phishing** (unseen) | catches 96 %; wrongly flags 16 % of ordinary sites; ROC-AUC 0.96 |
| End-to-end feature check (43 URLs, 8 messages, guarantee, screenshots, SSRF …) | 97/97 on the live site |
| Unit and property tests | 487/487 |
| Sample set (27 messages) | 12/12 legitimate allowed, 15/15 phishing caught |

The URL model's 16 % false-alarm rate on unfamiliar sites is why it never decides alone. Testing on live data during this
project found and fixed a dataset artifact: the model had learned "no `www.` = phishing" and flagged 76 % of real sites.
It also found a reported miss (`gitbuh.io` imitating `github.io`, letters swapped two apart), which led to the new
permutation detector.

## 6. Privacy and safety

- Screenshots are read on the device; only text is sent.
- Only public indicators (hosts, URLs without personal tokens) are ever sent to third-party services.
- Every network lookup passes an SSRF guard: private, loopback, link-local and cloud-metadata addresses are refused.
- Mail is never deleted. Live quarantine requires explicit configuration.
- Sample data is labelled DEMO DATA everywhere and can be removed with one click.
- Feed lists can never mark a whole shared service (link shorteners, hosting platforms, top sites) as malicious.

## 7. Clients

- **Dashboard.** A dark enterprise console with 14 pages, a ⌘K command palette, live updates, the Training & validation
  history, and support for phones and tablets (it can be installed to the home screen).
- **Chrome extension.** Checks pages as you open them, shows a full-page warning with the evidence, adds Gmail verdict
  banners and a right-click "check link". It works without setup.

## 8. How it runs on Vercel

- Each deploy builds a data snapshot: the sample data, the feed graph, and 280,000 domains from the large feeds.
- Every server instance starts from that snapshot in seconds. The first request after the site goes idle takes about
  11 s; after that, responses take about 0.5 s.
- The dashboard's files come from Vercel's CDN.
- Analysis history is per instance and temporary, because serverless instances have no shared disk. The **model and
  test history is permanent**, because it lives in the repository.

## 9. What still needs you

| To get | Do this |
|---|---|
| VirusTotal, urlscan, Google Safe Browsing, OTX, AbuseIPDB, PhishTank answers | Create free accounts and set the keys (`.env.example` lists the names; on Vercel: Project → Settings → Environment Variables). The dashboard shows `NOT CONFIGURED` until then, never "clean". |
| Analysis history that persists and is shared across instances | Create a hosted Postgres (e.g. Neon, Supabase) and set `DATABASE_URL`. |
| Real quarantine instead of simulated | Mailbox credentials plus `RESPONSE_LIVE_ACTIONS=true` (IMAP copy-and-flag; never delete). |
| The semantic (MiniLM) stage on Vercel | It needs PyTorch, which exceeds Vercel's function size. It runs locally and in Docker. |

## 10. A two-minute demo for judges

1. Open **Overview**: live KPIs, detections per hour, campaigns.
2. **Analyze → Screenshot**: paste a screenshot of an SBI KYC SMS. Watch the scan beam, check the extracted entities,
   then analyse. You get BLOCK with the evidence.
3. Press ⌘K and paste `gitbuh.io`. The investigation says "uses the letters of github in a different order".
4. Open **Threat graph**: today's real phishing infrastructure, by brand and hosting platform.
5. Open **Training & validation**: every model version, 487 tests and the live 97/97 feature check, each run expandable.
6. Show the Chrome extension's warning page on a flagged site.

## Evidence (reproduce everything)

```bash
python scripts/run_tests.py            # 487 unit + property tests, recorded
python scripts/feature_check.py        # 97 end-to-end checks (add --base https://phishgraph.vercel.app --no-feedback)
python scripts/eval_fresh_feed.py      # deployed URL model vs today's live phishing
python scripts/eval_lookalike.py       # 50,000 real domains + generated attacks
python scripts/train_all.py            # retrain; versions in models/registry.json
```
Results land in `data/validation/history.json`, `models/*/report.json` and `data/processed/`, and are shown on the
dashboard's Training & validation page.
