# PhishGraph design system

A dark-first threat-intelligence platform: a graph investigation workspace, a command centre, and a premium developer
tool. It should read as a real security product, not a generated dashboard.

## How it was decided: every frontend skill, compared

Each installed frontend skill was run against the brief. Its output was kept only where it helped the product look
less generic:

| Skill | Kept | Rejected (reads as AI-generated) |
|---|---|---|
| **dataviz** *(the winner)* | Validated **status palette**; the rule that **text wears ink, colour lives in marks** (dots, rules, bars, rings); icon + label on every status; hover layer; table as the accessible source of truth | none |
| **ui-ux-pro-max** | "Real-time / operations" landing pattern; "live" only when backed by a source; static final frame under reduced motion; step indicators for multi-step work; empty states with an action; `inputmode` on mobile | Cyberpunk style (neon matrix green), Cinzel typeface |
| **brand** | Voice: formal-leaning, technical, serious, reserved. Traits: precise not dramatic; evidence-led not hype; calm under threat | none |
| **ui-styling** | Dialog focus trap, Esc, focus return; grouped command palette | The shadcn/ui default look (the v0 aesthetic) |
| **design-system** | State priority (disabled > loading > active > focus > hover); 150 ms colour / 200 ms transform transitions; token validator | none |
| **design** | Cybersecurity mark guidance (shield + technical, never "weak/exposed"); one consistent stroke icon set | Gemini logo and icon generation |

The biggest single difference between a real security product and an AI dashboard is **not painting numbers red and
orange**. Every risk number, KPI and score is now ink; severity is carried by a mark beside it.

## Identity

- **Mark** (`components/brand/PhishGraphLogo.tsx`, mirrored by `public/favicon.svg`). A shield drawn *as graph edges*
  with nodes on its vertices, and a hook descending from the top node whose barb ends in a red threat node. It means
  network, protection and phishing without being literal. It is used in the navbar, the favicon and app icons, the
  extension, the loader and empty states.
- **Type.** IBM Plex Sans for the interface and JetBrains Mono for data (domains, IPs, hashes, IDs) and the small
  uppercase eyebrows. The hero is 60 px, sections 30–36 px, cards 15–17 px, metadata 10.5–12 px.
- **Palette.** Near-black `#05070d` with graphite surfaces, one electric accent (`#38bdf8` → `#3b82f6`), and thin
  borders with an 18 % gradient edge on glass panels. There is no glowing text.
- **Severity** (dataviz status palette; the same in both themes; each one ≥ 3:1 on the dark surface):
  LOW `#0ca30c` · MEDIUM `#fab219` · HIGH `#ec835a` · CRITICAL `#d03b3b`.
  These map to the verdicts ALLOW / FLAG / QUARANTINE / BLOCK. They are always shown with a label (and a shape on pills).
  - A categorical check failed our previous four-orange set: MEDIUM and HIGH were nearly identical for colour-blind
    users (ΔE 0.6). The status palette separates them by hue family.
- **Corners.** 8 px cards, 6 px controls, 4 px badges.

## Motion (CSS and SVG only; no animation library; everything stops under reduced motion)

| Where | What |
|---|---|
| Hero | Canvas network: packets travel edges, threat nodes pulse. It pauses offscreen or when the tab is hidden, and is captioned "illustration, not live data". |
| Investigation | Stage list (✓ / ◉ / ○) with a small network constructing itself, one node per stage. |
| Graph | Nodes and edges reveal outward from the focus in breadth-first order (discovery). Known-bad nodes pulse; packets run only on edges touching a threat or the selection (at most 36). |
| Score | A 270° gauge sweeps with an animated number; contributing-factor bars grow. |
| Timeline, evidence | Staggered entry (70 ms per item). |
| Drawers, toasts, palette | 200–280 ms ease-out; exits faster than entries. |

## Screens

- **Landing** (`/`): hero with the investigation bar, **live metrics from the API**, how it works, a **real
  infrastructure graph**, the actual intelligence sources (keyless ones on; keyed ones marked "with your key"),
  capabilities, and a call to action.
- **Investigation workspace** (`/investigate`): breadcrumb and live status; the command-centre bar (validation,
  clear, Enter, `/` to focus, recent and example queries); staged loader; then three panes:
  - **Entity:** DNS, RDAP, ASN, nameservers, TLS and brand evidence, all real.
  - **Graph:** this investigation's own graph.
  - **Score, evidence, intelligence sources and timeline:** the timeline is built only from dated real facts.
  - Below them, the full explainable report.
  Error and empty states give reasons and a retry.
- **Graph** (`/graph`): icon per entity type, hover metadata, click to focus, **double-click (or E) to expand real
  relationships**, full-screen mode, a details drawer with copy buttons and clickable relationships, and a table view.
- **Shell:** translucent navbar (Investigate · Graph · Intelligence · Documentation) and a sidebar with only real
  sections (Investigate / Workspace / Intelligence / System). ⌘K opens a grouped command palette with a focus trap; `?`
  shows shortcuts. Toasts confirm actions. On phones there is a bottom navigation with 5 items and a drawer sidebar.

## Accessibility and performance

- Visible focus everywhere and a skip link. Graph entities are focusable buttons with labels. Dialogs trap focus.
  `aria-live` is used for progress and status. Nothing is shown by colour alone.
- The main bundle is about 71 KB of gzipped JavaScript, and every route is lazy-loaded. `lucide-react` is the only UI
  dependency added (tree-shaken). There are no chart, graph or animation libraries. OCR is loaded on demand.
