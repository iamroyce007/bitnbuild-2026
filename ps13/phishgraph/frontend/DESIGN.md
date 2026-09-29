# PhishGraph console: design notes

## Direction: dark-first enterprise security console

The brief was "flashy enterprise security software", the category of CrowdStrike Falcon, Palo Alto Cortex and Wiz.
From the ui-ux-pro-max skill we took **Glassmorphism** (style match: 10–20 px backdrop blur, 1 px translucent borders,
layered depth, performance cost low) and the "security blue" family from its palette search. The skill's other palette
results for this query were off-topic (insurance and podcast products), so the rest of the palette is our own and marked
as such here.

Deliberately not used: neon "matrix" green, purple-to-pink gradients and glitch effects. They read as generic
"hacker" or AI templates. Colour carries meaning. One electric accent (sky → blue) is used for interaction and
emphasis, and the severity colours are used only for verdicts.

| Token | Dark (default) | Light | Use |
|---|---|---|---|
| bg / surface / surface-2 | #05070d / #0b1020 / #121a31 | #eef2f8 / #ffffff / #f3f6fb | page, glass panels, table heads |
| line / line-strong | #1b2440 / #2b3860 | #e1e7f0 / #c9d3e2 | rules and control borders |
| ink / muted / faint | #e9eefc / #a3b0cf / #7584a8 | #0a1222 / #44516a / #5f6d86 | text (at least 4.5:1 on surface) |
| accent → accent-2 | #38bdf8 → #3b82f6 | #0369a1 → #2563eb | primary buttons, active nav, focus, glows |
| allow / flag / quarantine / block | #34d399 / #fbbf24 / #fb923c / #fb4d6d | #047857 / #a16207 / #c2410c / #be123c | verdicts only |

## Surfaces and effects (all CSS)

- **Glass cards:** a translucent surface with `backdrop-filter: blur(16px) saturate(140%)`, a gradient edge (the
  padding-box/border-box trick keeps rounded corners), and a deep soft shadow. Hovered cards lift and gain an accent glow.
- **Background:** a slow aurora (three radial gradients on a fixed layer, animated with transform only) over a 36 px
  grid that fades toward the bottom.
- **Top bar:** frosted chrome with a gradient hairline under it; the wordmark "Graph" and the active page use glowing
  gradient text; there is an "Enterprise" badge.
- **Navigation:** grouped; the active item gets a gradient pill and a glowing accent bar.
- **KPI tiles:** numbers count up and use gradient text (severity numbers glow in their own colour); a glowing top rule
  draws in, and a light sheen passes across.
- **Buttons:** primary buttons have a gradient fill with an accent glow and lift on hover; all buttons press to 0.97.

## Motion (CSS only; everything stops under prefers-reduced-motion)

| Where | What |
|---|---|
| Route change | page rises 10 px and fades in |
| Overview, report | children stagger in (the skill's "Stagger List" timing, rebuilt in CSS) |
| KPI tiles | count-up, glowing rule draws in, periodic sheen |
| Verdict | the risk dial sweeps to the score, ticked at the 30 / 60 / 85 thresholds |
| Charts, score bars | bars grow from the baseline |
| Screenshot OCR | a glowing scan beam sweeps the image; % progress |
| Live feed | new rows flash with the accent and fade |
| Live status | the dot pulses only while the stream is live |

## Interaction

- ⌘K / Ctrl+K command palette: paste a URL or domain to investigate it, jump to any page, or run common actions.
- Screenshots can be chosen, photographed, dropped, pasted with ⌘V, or pasted with **Paste from clipboard**. The button
  works on iPhone and iPad through Safari's paste bubble; elsewhere a paste box is the fallback.
- Phones and tablets get 44 px touch targets, 16 px inputs (no iOS zoom), safe areas, installation to the home screen, and
  no horizontal overflow at 375 px.
- Container queries let the report lay itself out by the width it is given.
- **Training & validation** (`/validation`) shows every model version and every recorded test run, with trends.

## Rules we hold to

- Severity is never shown by colour alone: pills carry a shape (○ △ ◇ ■) and the word.
- No emoji. SVG icons are hand-drawn paths.
- Weight: the main bundle is about 64 KB of gzipped JS; every route is lazy-loaded; OCR is a separate on-demand chunk;
  there are no chart, graph or animation libraries.
- The light theme stays fully supported; the choice is stored under `phishgraph.ui-theme`.
