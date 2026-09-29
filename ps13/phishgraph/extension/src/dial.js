// Semicircular risk dial, same geometry as the dashboard's RiskNumber: sweeps to the score, ticks at the
// 30 / 60 / 85 decision thresholds, and counts the number up. Static under prefers-reduced-motion.
const NS = 'http://www.w3.org/2000/svg';
const COLOR = { ALLOW: 'var(--allow)', FLAG: 'var(--flag)', QUARANTINE: 'var(--quar)', BLOCK: 'var(--block)' };
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

function node(tag, attrs) {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
}

export function riskDial(score, decision, width = 138) {
  const R = 46, C = Math.PI * R, arc = `M14 58 A${R} ${R} 0 0 1 106 58`;
  const color = COLOR[decision] || 'var(--faint)';
  const svg = node('svg', { viewBox: '0 0 120 66', width, height: Math.round(width * 0.55), class: 'dial', role: 'img', 'aria-label': `Risk ${Math.round(score)} of 100, ${decision}` });
  svg.append(node('path', { d: arc, fill: 'none', class: 'track', 'stroke-width': 9, 'stroke-linecap': 'round' }));
  const val = node('path', { d: arc, fill: 'none', class: 'value', stroke: color, 'stroke-width': 9, 'stroke-linecap': 'round', 'stroke-dasharray': C, 'stroke-dashoffset': C });
  svg.append(val);
  for (const t of [30, 60, 85]) {
    const a = Math.PI * (1 - t / 100), x = 60 + R * Math.cos(a), y = 58 - R * Math.sin(a);
    svg.append(node('line', { x1: x, y1: y, x2: 60 + (x - 60) * 0.78, y2: 58 + (y - 58) * 0.78, class: 'tick', 'stroke-width': 1 }));
  }
  const num = node('text', { x: 60, y: 56, 'text-anchor': 'middle', 'font-size': 28, 'font-weight': 600, fill: color, 'font-family': 'var(--sans)' });
  num.textContent = reduced ? Math.round(score) : '0';
  svg.append(num);

  const target = C * (1 - Math.max(0, Math.min(100, score)) / 100);
  // set as a style property (not an attribute) so the CSS transition runs
  if (reduced) { val.style.strokeDashoffset = `${target}px`; return svg; }
  val.style.strokeDashoffset = `${C}px`;
  requestAnimationFrame(() => requestAnimationFrame(() => { val.style.strokeDashoffset = `${target}px`; }));
  const start = performance.now();
  const tick = (t) => {
    const k = Math.min(1, (t - start) / 900);
    num.textContent = Math.round(score * (1 - Math.pow(1 - k, 3)));
    if (k < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
  return svg;
}

export function reasonItems(reasons) {
  return reasons.map((r) => {
    const li = document.createElement('li');
    const c = document.createElement('span');
    c.className = 'cat';
    c.textContent = r.category;
    const t = document.createElement('span');
    t.textContent = r.text;
    li.append(c, t);
    return li;
  });
}
