// Offline accuracy check for the fusion engine + acoustic self-mapping.
const { makeGrid, localize, pathLoss, rangingDistances, mds2d, C, DETECT_MARGIN } = require('./fusion');
const gauss = () => { let u = 0, v = 0; while (!u) u = Math.random(); while (!v) v = Math.random(); return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v); };

const bounds = { w: 24, h: 16 };
const grid = makeGrid(bounds, 0.4);
const nodes = [
  { id: 'a', x: 3, y: 3 }, { id: 'b', x: 21, y: 3 }, { id: 'c', x: 21, y: 13 },
  { id: 'd', x: 3, y: 13 }, { id: 'e', x: 12, y: 8 }, { id: 'f', x: 12, y: 1.5 },
].map((n) => ({ ...n, floor: -62, gain: 0, syncSigma: 0.012 }));

let errs = [], single = [];
for (let trial = 0; trial < 200; trial++) {
  const sx = 1 + Math.random() * 22, sy = 1 + Math.random() * 14;
  const S = -15 + gauss() * 2;
  const hits = [];
  for (const n of nodes) {
    const r = Math.max(0.4, Math.hypot(n.x - sx, n.y - sy));
    const level = S - pathLoss(r) + gauss() * 3;
    if (level > n.floor + DETECT_MARGIN) hits.push({ nodeId: n.id, t: r / C + gauss() * 0.006, level });
  }
  if (!hits.length) continue;
  const res = localize({ cls: 'impact', hits }, nodes, grid);
  const e = Math.hypot(res.best.x - sx, res.best.y - sy);
  errs.push(e);
}
errs.sort((a, b) => a - b);
const q = (p) => errs[Math.floor(errs.length * p)].toFixed(2);
console.log(`Single-event localisation over ${errs.length} random knocks: median ${q(0.5)} m, p90 ${q(0.9)} m`);

// accumulate 6 knocks from one spot (what the heat map does)
const sx = 8.3, sy = 11.1;
const acc = new Float32Array(grid.n);
for (let k = 0; k < 6; k++) {
  const hits = [];
  for (const n of nodes) {
    const r = Math.hypot(n.x - sx, n.y - sy);
    const level = -15 - pathLoss(r) + gauss() * 3;
    if (level > n.floor + DETECT_MARGIN) hits.push({ nodeId: n.id, t: r / C + gauss() * 0.006, level });
  }
  const res = localize({ cls: 'impact', hits }, nodes, grid);
  for (let i = 0; i < grid.n; i++) acc[i] += res.post[i];
}
let bi = 0; for (let i = 0; i < grid.n; i++) if (acc[i] > acc[bi]) bi = i;
console.log(`Fused over 6 knocks: error ${Math.hypot(grid.xs[bi] - sx, grid.ys[bi] - sy).toFixed(2)} m`);

// ranging
const ids = nodes.map((n) => n.id);
const arrivals = {};
ids.forEach((i, a) => {
  arrivals[i] = {};
  ids.forEach((j, b) => {
    const pi = nodes[a], pj = nodes[b];
    const r = i === j ? 0.12 : Math.hypot(pi.x - pj.x, pi.y - pj.y);
    arrivals[i][j] = b * 0.75 + 0.05 * b + r / C + gauss() * 0.0002 + 7 * a;
  });
});
const D = rangingDistances(ids, arrivals);
const { points, stress } = mds2d(D);
const d01 = Math.hypot(points[0].x - points[1].x, points[0].y - points[1].y);
console.log(`Auto-Map: stress ${(stress * 100).toFixed(1)}%, a-b distance ${d01.toFixed(2)} m (true 18.00 m)`);
