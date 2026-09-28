# PhishGraph dashboard: design notes

Direction from the ui-ux-pro-max design-system query "cybersecurity SOC threat monitoring dashboard dark"
(density 8, motion 2, variance 3): **Minimalism / Swiss style**, Fira Sans + Fira Code, dense dashboard spacing.

Deliberate deviation: the suggested primary colour was neon "matrix" green (#00FF41). It reads as a hacker cliché
and competes with the severity scale, so the base is neutral black-slate and colour is reserved for meaning.

| Token | Value | Use |
|---|---|---|
| bg / surface / surface-2 | #07090c / #0e1217 / #141a21 | page, cards, raised controls |
| line / line-strong | #1d242d / #2a3440 | hairline borders |
| ink / muted / faint | #e6e9ed / #94a0ae / #66717e | text hierarchy (ink and muted pass 4.5:1 on bg) |
| accent | #4d8eff | actions and links only |
| allow / flag / quarantine / block | #2fbf71 / #e0a106 / #f07038 / #ff4d4f | decision severity |

Rules we hold to
- Severity is never colour alone: decision pills carry a shape (○ △ ◇ ■) and the word; charts have text equivalents.
- No emoji, no gradients, no glass or blur; SVG icons are hand-drawn paths.
- Live data shows its state (Live / Polling / Offline), a last-refresh time, a pause control, and a polite live region.
- Every route is lazy-loaded; first load is about 65 KB gzip. No chart or graph libraries: charts are SVG and the
  graph uses a small component-packed Fruchterman-Reingold layout computed once (no animation loop).
- Reduced motion is respected; focus rings are always visible; the graph has a tabular equivalent.
