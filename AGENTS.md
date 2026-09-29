# AGENTS.md: guide for AI agents working on this repository

This repository contains **PhishGraph** (`ps13/phishgraph/`), a real-time phishing detection and response platform built for
Bit N Build 2026, problem statement PSN013 (*NLP + graph-based analysis to catch sophisticated phishing emails/links as they
arrive, including attacks designed to evade traditional filters, and block or flag them instantly*).

Read this whole file before changing code. It explains what each part does, the invariants you must not break, and how to
verify your work. Paths below are relative to `ps13/phishgraph/` unless they start with `/`.

---

## 1. One-paragraph mental model

A message (email / SMS / WhatsApp / URL) is parsed and de-obfuscated, its links are extracted, and six independent engines
score it: **NLP** (text), **URL** (lexical ML + rules), **brand** (look-alike domains), **metadata** (sender / headers /
attachments), **threat intelligence** (external providers + local feeds) and **graph** (relationships to known-bad
infrastructure). A fusion engine combines them with configurable weights, a *corroboration rule*, and hard floors/caps into a
0–100 risk and a decision (ALLOW / FLAG / QUARANTINE / BLOCK). Everything that contributed is returned as explicit evidence.
The message and its entities are written into a temporal property graph; suspicious messages are clustered into campaigns. A
simulated response is recorded, a WebSocket event is emitted, and a background job later enriches the message
(DNS / RDAP / TLS / ASN / external intel) and re-scores it. Analysts confirm or reject detections; that feedback flows into
the local threat feed, the graph, and a retraining queue.

## 2. Repository layout

```
/AGENTS.md, /CLAUDE.md, /README.md      repo-level docs (this file is the source of truth for agents)
/.gitignore                              raw datasets, venvs, node_modules, DB files, build output are ignored
ps13/
  .venv/                                 local virtualenv (ignored); Python 3.14 locally, 3.12 in Docker
  phishgraph/
    backend/app/                         FastAPI service + all detection engines (Python)
    backend/tests/                       pytest suite (90 tests)
    frontend/                            React + Vite + Tailwind dashboard (TypeScript)
    extension/                           Chrome MV3 extension (plain JS, no build step)
    scripts/                             dataset download, demo seed/attack, training, evaluation, load test
    models/                              trained artifacts (committed, ~15 MB) + registry.json + reports
    data/brands.json                     curated brand knowledge base (95 brands)
    data/demo/demo_dataset.json          DEMO DATA (fictional infrastructure, labelled)
    data/raw/                            downloaded datasets (ignored; see data/DATASETS.md)
    data/processed/                      evaluation outputs + runtime feedback queues (*.jsonl ignored)
    Dockerfile, docker-compose.yml       production-style deployment (Postgres, Redis, Neo4j, API, worker)
    README.md, SECURITY.md, data/DATASETS.md, frontend/DESIGN.md
```
`ps01/` (an unrelated earlier project) exists on the author's disk but is intentionally **not** part of this repository.

## 3. Backend (`backend/app/`)

### Entry and configuration
| File | Responsibility |
|---|---|
| `main.py` | App factory. Lifespan: run migrations, warm models (brand index, URL model, NLP, intel store), start in-process job workers, the feed scheduler and (if configured) the mailbox loop. Adds CORS (incl. `chrome-extension://`), a metrics middleware, `/health`, `/ready`, `/metrics` (Prometheus text), the WebSocket `/api/v1/events`, a polling fallback `/api/v1/events/recent`, and serves `frontend/dist` as an SPA. |
| `config.py` | `Settings` (pydantic-settings). Every knob comes from env / `.env`: storage URLs (empty = local fallback), API keys, SSRF switch, provider keys, feature flags, fusion weights `W_*`, thresholds `T_*`, Tranco sizes, `GRAPH_PATH`. `get_settings()` is cached. |
| `database.py` | SQLAlchemy engine (`postgresql://` is rewritten to `postgresql+psycopg://`; SQLite gets WAL), `session_scope()` context manager, `init_db()` → migrations. |
| `migrations.py` | Ordered idempotent migrations tracked in `schema_migrations`. Add a new `_m000N_*` function and append it to `MIGRATIONS`; never edit an applied one. |
| `models/database_models.py` | Tables: users, emails, urls, email_urls, domains, ips, detections (full report JSON), threat_intelligence, iocs (local feed), campaigns (with centroid embedding), feedback, response_actions, audit_logs, model_versions, drift_snapshots. |
| `models/schemas.py` | Pydantic request/response schemas (also drive OpenAPI at `/docs`). Size limits live here. |

### API (`api/`)
| File | Routes |
|---|---|
| `deps.py` | `require_key` (X-API-Key or `?api_key=`, constant-time compare against `API_KEYS` or hashed `users`). With `PUBLIC_ACCESS=true` a request **without** a key is served as client `public` (a wrong key is still 401); `resolve_client()` is shared with the WebSocket. Token bucket per key, or per client IP (`X-Forwarded-For`) for public requests. `audit()`, in-memory `METRICS`. |
| `routes_analyze.py` | `POST /analyze/email` (JSON or `raw`), `/analyze/eml` (upload), `/analyze/url`, `/extract` (OCR text of a screenshot → structured message + entities; or re-extract entities from reviewed `fields`), `/investigate` (202 + job; SSRF-checked up front), `GET /jobs/{id}`. |
| `routes_data.py` | detections list/detail, graph (detection / domain / overview), domain & IP views, campaigns list/detail, feedback, threat-feed list/add, statistics (continuous hourly buckets), providers, models (+ drift), `GET/POST/DELETE /sample-data`, `POST /feeds/refresh`. |

### The detection pipeline (`services/`), in execution order
| File | Responsibility |
|---|---|
| `email_parser.py` | `parse_raw_email()` (stdlib `email`, policy.default) and `parse_json_message()` → `ParsedMessage` (sender, auth results SPF/DKIM/DMARC, reply-to, return-path, attachments hashed with risky/double-extension flags, headers). Calls the normaliser and extractor. |
| `text_normalizer.py` | `html_to_text()` (hidden-text detection, anchors, buttons, meta refresh, forms, password fields) and `deobfuscate()` (zero-width, mixed-script words → skeleton, defanging, spaced letters, base64 links). Returns the tricks found as evidence. |
| `url_extractor.py` | All URLs from text / anchors / forms with provenance and *deceptive link text* detection; phone numbers, UPI IDs, crypto wallets. |
| `screenshot_extractor.py` | Not part of analysis: turns OCR text from a phone/mail screenshot into `{channel, sender, subject, body, entities, repairs, removed_lines, warnings}`. `_CHROME` patterns drop UI text (status bar, ticks, bubble times, Gmail chips, WhatsApp notices); `_layout()` knows iPhone/Android Messages, WhatsApp, Gmail app/web, Outlook (Gmail's "to me" line is kept as an anchor for the sender); `_repair_links()` fixes wrapped links, `https;//`, spaced dots, and lists every repair. **Never rewrites look-alike characters** (`g00gle` stays). `fields=` skips layout and only re-extracts entities from reviewed text. Tests: `tests/test_screenshot.py` (one transcript per app layout). |
| `sample_data.py` | Removable sample data: `load()` seeds the DEMO feed/infrastructure and replays the 27 demo messages with `demo=True`; `clear()` deletes them and prunes orphaned graph nodes; `active()` also drives the demo DNS overlay. |
| `nlp_features.py` | Tokeniser shared by training and inference (drops corpus-artifact tokens like `enron`). |
| `nlp_engine.py` | Stage 1 TF-IDF LR (+ exact top-term contributions), stage 2 MiniLM LR (optional), 20 multilingual intent categories (`INTENTS` regexes with evidence spans) and semantic prototypes (`PROTOTYPES`, cosine ≥ 0.55). Without any intent, the ML probability counts at 60% (it over-flags transactional notices). |
| `url_features.py` | 37 lexical features (`FEATURE_NAMES`) + `char_ngrams()`; the single source of truth for training and inference. `is_https` was removed on purpose (dataset artifact). |
| `url_engine.py` | Calibrated blend (char n-gram LR + HGB, isotonic), deterministic rules with weights, brand verdict, top n-gram reasons. **ML alone weighs 0.45; with a corroborating rule 0.8. Official/established domains are capped.** |
| `brand_engine.py` | The look-alike engine. Protected = curated brands + Tranco top `TRANCO_PROTECT_TOP` labels. Finds `homograph`, `substitution`, `typosquat` (deletion index on `tkey` = skeleton with `rn`→`m`), `subdomain_spoof`, `combosquat` (curated keywords, exact/affix/1-typo, `SCAM_AFFIXES`, `COMMON_WORD_KEYWORDS`), `tld_swap` (curated only; ccTLDs weak). Also `claimed_brands(text)` (precompiled patterns). |
| `metadata_engine.py` | Sender look-alike, display-name spoof, free-mail posing as an institution, reply-to / return-path mismatch, auth failures, risky attachments, SMS personal-number vs registered DLT header, evasion tricks. Emits `trust` signals (official non-free-mail sender without auth failures; DLT header matching the brand). |
| `threat_intel.py` | `ThreatIntelOrchestrator.lookup_many()` runs every provider concurrently; noisy-OR score weighted by confidence. **`available` is true only if there is a hit or a real external answer**; a local feed miss is not evidence of safety. |
| `intel_store.py` | In-memory index over the `iocs` table: exact URL, exact host, and domain-level matches, **never** for Tranco top-100k, free-hosting or official-brand registrable domains (a phishing form on docs.google.com must not taint google.com). `add()` persists and indexes. |
| `graph_store.py` | `NetworkXStore` (MultiDiGraph persisted to `GRAPH_PATH` / `data/graph.json`) and `Neo4jStore` (MERGE-based writes, k-hop reads back into NetworkX). Node ids are `type:key`. Edges carry first/last seen, source, confidence, count. `subgraph()` does not expand through nodes with degree > 150. |
| `graph_engine.ingest_feed()` | Live feed URLs → url/domain nodes, `IMPERSONATES`/`TARGETS` brand edges and `ABUSES` platform edges (free hosting); skips official/established hosts; no network calls. |
| `graph_engine.py` | `ingest()` writes email/sender/url/domain/ip/asn/ns/cert/brand/feed nodes and relations; `score()` computes the 7 weighted components with **hub dampening** (`_specificity`; shared CDN ASNs and registrar-default nameservers ≈ 0; paths through infrastructure with specificity < 0.3 are ignored) and returns grouped, human-readable paths. `mark()` sets malicious/benign. |
| `campaign_engine.py` | `match()` (vectorised semantic similarity to campaign centroids + cached per-campaign infrastructure overlap + brand + time) and `assign()` (join ≥ 0.55 or create when risk ≥ 60). IDs `CAMPAIGN-<year>-<NNNN>`. `_INFRA_CACHE` is invalidated on change. |
| `brand_guard.py` | **The guaranteed rule**: a message presenting itself as protected brand B, not from B's verified sender (official domain without auth failure, or matching DLT header), with any link outside B's family's official domains (user-content hosts like `sites.google.com` never count) → at least FLAG, applied last in `fuse()`, report gets `brand_guard` + an "go to the official site" reason. Exhaustive test: `tests/test_brand_guard.py` (95 brands × 4 cases). |
| `risk_engine.py` | `fuse()`: renormalised weights over available sources; peak rule (a ≥ 85 signal is not diluted below 85%); floors (known-bad IOC 92; strong brand look-alike + language ≥ 40 → 85); evasion +8; all-links-trusted cap; **corroboration cap** (0 families → 40, 1 → 55); trust ×0.6; conflicting-intelligence detection. `decide()` uses `T_*`. |
| `explainability.py` | `build_report()`: the JSON report stored in `detections.report` and shown everywhere: reasons (category, text, weight, engine source), per-source TI status with `SOURCE UNAVAILABLE` / `NOT CONFIGURED`, message with intent highlight spans, URLs with brand/enrichment, graph paths, campaign, deception timeline. |
| `pipeline.py` | `analyze()` orchestrates everything (fast path) and `deepen()` (background re-score with enrichment). Computes the evidence-family count for the corroboration rule, persists, responds, publishes events, and queues `deepen` for untrusted links. |
| `response_engine.py` | Simulated by default; BLOCK adds untrusted URLs to the local feed (`phishgraph_block`); live IMAP quarantine only with `RESPONSE_LIVE_ACTIONS`. Writes `response_actions` + `audit_logs`. |
| `feedback_engine.py` | Confirm / false positive / unsure → IOC store, graph marks, `data/processed/*.jsonl` training queues, audit log, event. |
| `investigation.py` | Unknown-URL full chain = `analyze(kind='investigation', deep=True)` after an SSRF check. |
| `validation_log.py` | Testing history: `append(kind, summary, details)` → `data/validation/history.json` (kinds `unit_tests`, `feature_check`, `fresh_feed`, `lookalike`). Written only by scripts that ran; served by `GET /api/v1/validation` with the model registry. |
| `monitoring.py` | Drift report: PSI of risk scores (24 h vs before), flag ratio, reviewed FP rate, confidence histogram, new TLDs and impersonated brands, model metrics from the registry. |
| `events.py` | In-process pub/sub for WebSocket clients (mirrored to Redis pub/sub when available). |

### Connectors, utilities, workers, ML
| File | Responsibility |
|---|---|
| `connectors/base.py` | `Connector` base: configured/enabled gating, privacy filter `safe_indicator()`, cache, rate limiter, circuit breaker, retries with exponential backoff, `TIResult` with explicit `status`. |
| `connectors/providers.py` | VirusTotal, urlscan (search history first), Google Safe Browsing, OTX, AbuseIPDB, URLhaus, `LocalIntel` (ttl 0: always live). `ALL` lists them. |
| `connectors/mailboxes.py` | IMAP / Gmail API / Microsoft Graph polling loop and IMAP quarantine (copy + flag; never delete). |
| `utils/unicode_utils.py` | UTS #39 skeleton from `data/raw/confusables.txt`, script detection, punycode helpers, zero-width set. |
| `utils/url_utils.py` | PSL-based `split_host()`, `parse_url()`, static unwrapping of safe-link/tracking wrappers (incl. regional subdomains), SSRF checks (`ssrf_block_reason`, `is_public_ip`). |
| `utils/dns_utils.py` | DNS, Team Cymru ASN, RDAP, TLS certificate (handshake only), `enrich_host()`; `DEMO_MODE` overlay for the fictional demo domains (`_demo_enrichment`). |
| `utils/cache.py` | TTL cache (Redis or memory), `RateLimiter`, `CircuitBreaker`. |
| `workers/queue.py` | Job queue (in-process asyncio pool, or Redis list when `REDIS_URL`); jobs: `deepen`, `investigate`, `refresh_feeds`. |
| `workers/run.py` | Standalone Redis worker process. |
| `workers/feed_collector.py` | Feeds + scheduler. Keyless: OpenPhish, URLhaus (URLs; also put into the graph via `graph_engine.ingest_feed`), CERT Polska, Phishing Army (~280k domains; bulk-inserted). Keyed: PhishTank. `run_one()` records per-feed `STATUS`. |
| `ml/train_url.py`, `ml/train_email.py` | Training with random / domain-grouped / cross-source / cross-channel evaluation; artifacts → `models/`; registered in `models/registry.json` via `ml/model_registry.py`. URL: features are computed on the **canonical** URL (no scheme, no `www.`: a dataset artifact), Tranco homepages are added as training-only legitimate data (held-out rank ranges excluded), and `fresh_feed_eval()` scores the deployed model on today's OpenPhish vs held-out Tranco. Email: reviewed analyst feedback joins the deployed fit only (demo excluded, de-duplicated). |

## 4. Invariants (do not break these)

1. **No fabricated evidence.** Reasons, TI summaries and timeline events must come from computed data. Never add hard-coded
   "detections", never phrase an unperformed lookup as if it happened. Unavailable providers must say so.
2. **Missing ≠ safe.** Sources without evidence are excluded from fusion (weights renormalised), not scored 0.
3. **Corroboration rule** in `risk_engine.fuse()`: without a hard indicator, QUARANTINE/BLOCK needs ≥ 2 evidence families
   (computed in `pipeline.analyze()`).
4. **Look-alike false positives.** Official brand domains, their subdomains, brand TLDs and the Tranco top 100k are never
   look-alikes. Run `backend/tests/test_domains.py` and `scripts/eval_lookalike.py` after any brand-engine change and report
   the before/after numbers.
5. **Hub dampening** in `graph_engine._specificity()` must stay; shared CDN / registrar infrastructure must not link sites.
6. **Privacy / SSRF.** Only public indicators leave the system (`safe_indicator`); never fetch page content from the API
   process; all network enrichment goes through the SSRF checks.
7. **Demo data is labelled** (`demo=True`, `DEMO DATA`), uses documentation IP/ASN ranges, and is only present when loaded
   (`DEMO_MODE` or **Load sample data**); it is removable. Production and the public demo start with real data only.
8. **Feature/tokeniser parity.** `url_features.py`, `nlp_features.py` are shared by training and inference; changing them
   requires retraining (and the models were pickled with scikit-learn 1.8.0; keep the pin).
9. **Response safety.** Default is simulated. Never add code that deletes mail.
10. **Screenshots stay on the device.** OCR runs in the browser; only text reaches `/extract`. The extractor may remove UI
    chrome and repair link *formatting*, but must never change characters inside a domain (that would hide a homograph).
11. **The brand guarantee must hold for every brand.** `tests/test_brand_guard.py` must pass; never add a cap or discount after
    the guard in `fuse()`.
12. **Test history is never edited by hand.** Only scripts append to `data/validation/history.json`; failed runs stay.

## 5. Frontend (`frontend/`)

Lightweight by design (~64 KB gzip first load): React 18, React Router 6, Tailwind v4; **no chart, graph or animation
libraries** (motion is CSS). OCR (tesseract.js) is a separate chunk loaded only when a screenshot is read; its WASM and
language data come from jsDelivr on first use.
- `src/App.tsx`: shell (ink top bar, grouped sidebar with highlighter on the active page, ⌘K command palette, theme
  switch, page transitions), lazy routes, live-status context (`useLive`), sample-data context (`useSample`) and the
  sample-data banner. No sign-in screen: public servers need no key; a private server shows a short "this server is
  private" notice (a key can arrive once via a `#key=` setup link, `lib/api.ts`).
- `src/lib/`: `api.ts` (typed client; sends `X-API-Key` only when one is stored), `types.ts` (mirrors the report JSON),
  `events.ts` (WebSocket → polling fallback), `useApi.ts`, `ocr.ts` (image prep: enlarge small crops, reduce huge ones
  under iOS Safari's canvas limit, invert dark mode; HEIC fallback via `<img>`), `capture.ts` (**clipboard on every
  device**: `readClipboard()` must be the first await in a tap handler for iOS; throws `ClipboardUnavailable` so the UI
  shows `PasteTarget`, a box that takes a real long-press/⌘V paste; `extractFromImage/Text`; `looksStructured()`).
- `src/components/`: `ui.tsx` (primitives, `NAV_GROUPS`, breadcrumbs, count-up KPIs, risk dial, skeleton loader; pills use
  shape + word), `charts.tsx` (SVG), `GraphView.tsx`, `ReportView.tsx` (container queries, so it fits beside a form or full
  width), `DetectionTable.tsx` (new rows flash), `CommandPalette.tsx`, `ScreenshotInput.tsx` (pick → reading with scan beam
  → review with entity list), `FillFromCapture.tsx` (Email/SMS toolbar), `PasteTarget.tsx`.
- `src/pages/`: Overview, Feed, Analyze (Screenshot · Email · SMS/chat · Link · Raw .eml; pasting a whole email into
  Message splits it into fields, with Undo), Investigate (`?url=` starts at once), Detection, Graph, Campaigns, Campaign,
  Review, Intel, Models, **System health at `/system`** (not `/health`, which is the API health check), Setup, Settings.
- Phones/tablets: `(pointer: coarse)` gives 44 px targets and 16 px inputs (no iOS zoom); safe-area insets; installable
  (`public/manifest.webmanifest`, `apple-touch-icon.png`). Grids use `minmax(0,1fr)` and section bodies scroll sideways,
  so no page overflows at 375 px.
- Design rules: `frontend/DESIGN.md` (dark-first enterprise console: navy-black, glowing sky→blue accent, frosted-glass
  cards with gradient edges, aurora + grid background, IBM Plex Sans + JetBrains Mono, severity colours only for verdicts,
  CSS motion, reduced-motion respected). Theme key `phishgraph.ui-theme` (dark default).
- `pages/Validation.tsx` (`/validation`): model versions with per-split deltas and live-feed recall; every recorded run,
  expandable (per-file test results, every feature-check row, metrics), trend sparklines.

## 6. Chrome extension (`extension/`)

MV3, no build step, v1.3. Works out of the box against `https://phishgraph.vercel.app` (no key; a key is optional for
private servers). `src/background.js` (navigation checks → warning page for QUARANTINE/BLOCK, per-host cache, context
menus, `configure` from the dashboard via `connect.js`), `src/gmail.js` + `gmail.css` (banner above opened messages;
opt-in; built without `innerHTML` because Gmail enforces Trusted Types), `src/api.js` (settings, client, offline
structural checks), `dial.js` (shared risk dial), `ui.css` + `fonts.css` (same identity as the dashboard; fonts bundled
in `fonts/`, so no third-party requests), `warning.*`, `popup.*`, `options.*`. The dashboard serves it as a zip at
`/downloads/phishgraph-extension.zip` (built from the folder on first request).

## 7. Commands

```bash
cd ps13/phishgraph
python3 -m venv ../.venv && ../.venv/bin/pip install -r requirements-dev.txt [-r requirements-embeddings.txt]
../.venv/bin/python scripts/download_datasets.py [--reference-only] [--embeddings]
(cd backend && ../../.venv/bin/python -m pytest -q)                 # 487 tests, ~20 s, isolated temp DB/graph
../.venv/bin/python scripts/seed_demo.py --reset                     # DEMO DATA
../.venv/bin/python -m uvicorn --app-dir backend app.main:app --port 8000
../.venv/bin/python scripts/demo_attack.py                           # scripted demo against the running API
../.venv/bin/python scripts/feature_check.py [--base URL] [--no-feedback]  # end-to-end check of every feature + URL expectations (recorded)
../.venv/bin/python scripts/run_tests.py                              # pytest + record per-file results in the testing history
../.venv/bin/python scripts/eval_fresh_feed.py                        # deployed URL model vs today's live phishing (recorded)
../.venv/bin/python scripts/eval_lookalike.py                        # look-alike FP / recall numbers
../.venv/bin/python scripts/load_test.py --n 400 --concurrency 16    # needs RATE_LIMIT_PER_MINUTE raised
../.venv/bin/python scripts/train_all.py                             # retrain + re-evaluate (needs data/raw)
(cd frontend && npm ci && npm run build)                             # typecheck + build → served by the API
docker compose up --build                                            # full stack (not verified on the dev machine)
./scripts/deploy_vercel.sh                                           # Vercel: needs `npx vercel login` and .vercel-api-key
```

## 8. Testing expectations for changes

- Backend change → run the pytest suite; add a test for the behaviour you changed (tests live next to similar ones).
- Brand / URL / fusion change → also run `scripts/seed_demo.py --reset` and check the printed line
  `benign allowed: 12/12   phishing caught: 15/15`, plus `scripts/eval_lookalike.py` for brand changes.
- Frontend change → `npm run build` must pass (it runs `tsc -b`); check the page in a browser at 375 px and at desktop width.
- Screenshot / extraction change → add a transcript to `tests/test_screenshot.py` for the layout you touched.
- Before a deploy → `scripts/feature_check.py` against the local server; after it → `--base https://phishgraph.vercel.app --no-feedback`.
- Performance-sensitive change → `scripts/load_test.py` before and after; report both.
- Report numbers exactly as measured; if something could not be verified (e.g. Docker), say so.

## 9. Known limitations / good next tasks

- URL model cross-source generalisation is poor (F1 ≈ 0.61–0.64); more diverse legitimate URLs (deep links from Tranco
  sites) would help.
- Text model over-flags transactional notices on its own; add the collected hard negatives and retrain.
- Local graph is single-process; multi-worker deployments should use Neo4j.
- Docker Compose has not been executed yet; first run may need adjustments (e.g. Neo4j memory).
- Vercel: `scripts/deploy_vercel.sh` first runs `scripts/build_snapshot.py` (feeds + feed graph + sample data + large domain
  lists → `snapshot/`, git-ignored, bundled); `api/index.py` copies it to /tmp, indexes the lists in memory
  (`IntelStore.load_domain_list`, re-applied on reload), and re-fetches OpenPhish/URLhaus only when the snapshot is > 6 h old.
  `vercel.json` serves `/assets/*` and icons from the CDN via an `@vercel/static` build of `static/`.
- Vercel deploys must go through `scripts/deploy_vercel.sh`: `vercel.json` uses an explicit `@vercel/python` build (framework
  auto-detection and rewrites broke routing), the dashboard is bundled as `static/`, and uploads are git-free because Vercel
  blocks deploys whose commit author is not a verified team member (`TEAM_ACCESS_REQUIRED`).
- Ideas: landing-page screenshot similarity, certificate-transparency monitoring, learned fusion weights, Outlook add-in.

## 10. Commit conventions

Small, logical commits with imperative subjects prefixed by area (`Dashboard:`, `Extension:`, `Brand engine:` …), each ending with
the `Co-Authored-By` trailer used in history. Do not commit `data/raw/`, `.env`, databases, `node_modules`, `frontend/dist`
or `data/processed/*.jsonl`.
