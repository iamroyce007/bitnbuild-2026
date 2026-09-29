# PhishGraph console: design notes

## Direction: the evidence board

The skill (ui-ux-pro-max) was run with the brief "cybersecurity threat intelligence operations console distinctive"
(variance 6, motion 6, density 7). Its first style was **Cyberpunk UI** (matrix green on black, glitch effects).
We rejected it deliberately: neon green is the stock "hacker" look and reads as generic. From its alternatives we took:

- **Style:** Data-Dense Dashboard (compact grid, KPI row, sortable tables, row highlight on hover).
- **Type:** the "Developer Mono" pairing: IBM Plex Sans for the interface, JetBrains Mono for data (domains, IPs,
  hashes, IDs) and for small uppercase eyebrow labels.
- **Motion:** the skill's "Stagger List (Standard)" preset (300–450 ms, 50–60 ms stagger, soft overshoot), rebuilt in
  CSS so no animation library ships.

The identity is an analyst's evidence board: paper and graphite surfaces, ink-black primary actions, a faint dot grid
behind the workspace, and one signature colour, **highlighter yellow**, used the way an investigator marks evidence.
It marks the active page in the navigation, key headings, intent phrases in a message, and the "check what was read"
step after a screenshot. Severity colours are used only for verdicts.

| Token | Light (paper) | Dark (graphite) | Use |
|---|---|---|---|
| bg / surface / surface-2 | #ece9e1 / #faf8f3 / #f1eee6 | #0d0d0b / #151512 / #1c1c18 | board, cards, table heads |
| line / line-strong | #dcd6c8 / #c2baa6 | #292822 / #3b3931 | rules and control borders |
| ink / muted / faint | #17150f / #4a463c / #6b6557 | #ece7da / #aaa493 / #878171 | text (all at least 4.5:1 on surface) |
| primary / on-primary | #17150f / #faf8f3 | #ece7da / #0d0d0b | primary buttons, selected filters |
| mark | #ffd83d | #ffd83d at 38% | highlighter (background only, never text) |
| accent | #2140b8 | #93a8ff | links, focus ring |
| allow / flag / quarantine / block | #1d7a46 / #946400 / #c2410c / #c4122f | #3fca82 / #e8b21c / #f07a3f / #ff5d6c | verdicts |

## Motion (all CSS; disabled under prefers-reduced-motion)

| Where | What | Why |
|---|---|---|
| Route change | page rises 8 px and fades in (380 ms) | spatial continuity between pages |
| Overview, report | children enter in a stagger | shows reading order |
| KPI tiles | numbers count up; the severity rule draws in | draws the eye to change |
| Verdict | a semicircular dial sweeps to the risk score, with 30 / 60 / 85 thresholds ticked | the score is read against the thresholds |
| Score bars, charts | bars grow from their baseline | reads as measured data |
| Highlighter | the yellow mark swipes in left to right | a marker stroke, the product's signature |
| Screenshot OCR | a scan beam sweeps the image while text is read; % progress | honest progress for a slow step |
| Live feed | rows under 20 s old flash yellow and fade | new evidence is visible without reading timestamps |
| Live status | the dot pulses only while the stream is live | the pulse means "live", nothing else |
| Buttons | press scale 0.97; the primary button lifts onto a yellow offset shadow | tactile feedback |
| Loading | shimmer skeleton lines instead of "Loading…" | reserves the layout |

## Interaction

- ⌘K / Ctrl+K opens a command palette: paste a URL or domain to investigate it, jump to any page, analyse a
  screenshot, load sample data, or switch theme. It is keyboard first (↑ ↓ ↵ esc) and returns focus to where it
  was opened.
- Screenshots can be dropped, chosen, pasted with ⌘V, or pasted with the "Paste from clipboard" button. OCR runs
  in the browser; the image is never uploaded.
- The report uses container queries, so it lays out correctly both full width and beside the Analyze form.

## Rules we hold to

- Severity is never colour alone: pills carry a shape (○ △ ◇ ■) and the word; the dial has a text label.
- No emoji, gradients-as-decoration or glass. SVG icons are hand-drawn paths.
- Weight: every route is lazy-loaded, the main bundle is about 64 KB of gzipped JS, and OCR (tesseract.js) is a
  separate chunk fetched only when a screenshot is read. Fonts: two families, five weights, `display=swap`.
