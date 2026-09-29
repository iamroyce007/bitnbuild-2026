# PhishGraph console: design notes

Direction from the ui-ux-pro-max design-system query "enterprise security admin console B2B data tables"
(density 7, motion 1, variance 2): **Minimalism / Swiss style**, navy primary with a blue call to action,
built for enterprise and admin dashboards. The layout follows the familiar security-console pattern: a navy
top bar, a grouped left navigation (Monitor, Investigate, Intelligence, Administration), a breadcrumb over
every page title, KPI tiles, and dense tables.

Deliberate deviations
- The suggested typeface was Plus Jakarta Sans. We use the system UI font stack instead, so the console
  downloads no web fonts and paints with the operating system's native font (Segoe UI, San Francisco, Roboto).
- An earlier version was dark-only with neon severity colours. Enterprise users work in bright offices on
  shared screens, so light is the default. Dark is one click away in the top bar, and a "system" value in
  localStorage (`phishgraph.theme`) follows the OS.

| Token | Light | Dark | Use |
|---|---|---|---|
| bg / surface / surface-2 | #f3f4f6 / #ffffff / #f6f7f9 | #0b0e12 / #11161c / #171d25 | page, cards, table headers and hover |
| line / line-strong | #e1e4e8 / #c9ced6 | #232b35 / #323d4a | borders; line-strong on inputs and buttons |
| ink / muted / faint | #111827 / #4b5563 / #6b7280 | #e6e9ed / #a3adb9 / #7d8896 | text hierarchy (all at least 4.5:1 on surface) |
| chrome / chrome-ink | #13213a / #e8edf5 | #0e1319 / #e6e9ed | top bar |
| accent | #0a5cc2 | #5b9bff | primary buttons, links, active navigation |
| allow / flag / quarantine / block | #16803c / #a16207 / #c2410c / #be123c | #34c77b / #e0a106 / #f07038 / #ff5c5e | decision severity |
| neutral / campaign | #6b7280 / #7c3aed | #8a95a3 / #b48cff | graph nodes |

Every colour in components, charts and the SVG graph is a CSS variable from `src/index.css`, so both themes
come from one set of tokens. Translucent fills use `tint()` in `components/ui.tsx` (CSS `color-mix`), never hex
with an alpha suffix.

Rules we hold to
- Severity is never colour alone: decision pills carry a shape (○ △ ◇ ■) and the word; KPI tiles carry a
  label; charts have text equivalents.
- No emoji, gradients, glass or blur. SVG icons are hand-drawn paths.
- Monospace is only for indicators and data (domains, IPs, hashes, IDs). Labels and headings use the sans font.
- Live data shows its state (Live / Polling / Offline), a pause control, and a polite live region.
- Every route is lazy-loaded; first load is about 63 KB of gzipped JS, and there are no web fonts. There are no
  chart or graph libraries: charts are SVG, and the graph uses a small component-packed Fruchterman-Reingold
  layout computed once, with no animation loop.
- Reduced motion is respected, focus rings are always visible, and the graph has a tabular equivalent.
- The top-bar lookup opens `/investigate?url=…`, which starts the investigation at once.
