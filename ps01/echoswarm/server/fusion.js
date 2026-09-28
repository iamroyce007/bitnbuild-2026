// EchoSwarm fusion engine
// Turns a group of per-phone acoustic detections into a spatial probability map.
//
// Model per grid cell (candidate source position):
//   1. Level consistency  - received dB + 20log10(r) + debris loss should agree across
//                           detecting nodes (unknown source level solved in closed form).
//   2. Negative evidence  - nodes that did NOT hear it must be far enough away that the
//                           predicted level sits below their live noise floor.
//   3. Arrival-time (TDOA)- onset times, clock-synced over WebSocket, must be consistent
//                           with r/c. Weighted by each node's measured sync jitter.
//   4. Source-level prior - weak prior on how loud a knock/voice typically is at 1 m.

const C = 343; // speed of sound, m/s
const DEBRIS_LOSS_DB_PER_M = 0.35; // excess attenuation through rubble/air
const SIGMA_LEVEL = 5.5; // dB – phone mic + coupling variance
const DETECT_MARGIN = 7; // dB above floor needed to register an event
const SOURCE_PRIOR = { impact: -18, voice: -28, periodic: -45, other: -25 }; // dBFS at 1 m
const SIGMA_PRIOR = 14;
const SELF_D = 0.12; // typical speaker-to-mic distance on one handset (m)

function makeGrid(bounds, cell) {
  const cols = Math.max(4, Math.round(bounds.w / cell));
  const rows = Math.max(4, Math.round(bounds.h / cell));
  const xs = new Float32Array(cols * rows);
  const ys = new Float32Array(cols * rows);
  for (let r = 0; r < rows; r++)
    for (let c = 0; c < cols; c++) {
      xs[r * cols + c] = (c + 0.5) * cell;
      ys[r * cols + c] = (r + 0.5) * cell;
    }
  return { cols, rows, cell, xs, ys, n: cols * rows };
}

function pathLoss(r) {
  return 20 * Math.log10(r) + DEBRIS_LOSS_DB_PER_M * r;
}

/**
 * @param group  { cls, hits: [{nodeId, t, level}] }  t in seconds (server clock)
 * @param nodes  [{id, x, y, floor, gain, syncSigma}] – placed, live nodes only
 * @param grid   from makeGrid
 * @returns { post: Float32Array (normalised probability), best:{x,y,p}, spread }
 */
function localize(group, nodes, grid) {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const hits = group.hits.filter((h) => byId.has(h.nodeId));
  if (!hits.length) return null;
  const heard = new Set(hits.map((h) => h.nodeId));
  const silent = nodes.filter((n) => !heard.has(n.id));
  const s0 = SOURCE_PRIOR[group.cls] ?? SOURCE_PRIOR.other;

  const hx = hits.map((h) => byId.get(h.nodeId).x);
  const hy = hits.map((h) => byId.get(h.nodeId).y);
  const hl = hits.map((h) => h.level - (byId.get(h.nodeId).gain || 0));
  const ht = hits.map((h) => h.t);
  const hs = hits.map((h) => Math.max(0.004, byId.get(h.nodeId).syncSigma || 0.02));

  const logL = new Float32Array(grid.n);
  let maxL = -Infinity;
  const A = new Float64Array(hits.length);
  const tau = new Float64Array(hits.length);

  for (let k = 0; k < grid.n; k++) {
    const x = grid.xs[k], y = grid.ys[k];
    // 1. level consistency
    let sum = 0;
    for (let i = 0; i < hits.length; i++) {
      const r = Math.max(0.4, Math.hypot(x - hx[i], y - hy[i]));
      A[i] = hl[i] + pathLoss(r);
      tau[i] = ht[i] - r / C;
      sum += A[i];
    }
    const S = sum / hits.length; // ML source level at 1 m
    let cost = 0;
    for (let i = 0; i < hits.length; i++) cost += ((A[i] - S) / SIGMA_LEVEL) ** 2;

    // 2. negative evidence
    for (const n of silent) {
      const r = Math.max(0.4, Math.hypot(x - n.x, y - n.y));
      const pred = S - pathLoss(r);
      const thr = (n.floor ?? -60) + DETECT_MARGIN - (n.gain || 0);
      if (pred > thr) cost += ((pred - thr) / SIGMA_LEVEL) ** 2;
    }

    // 3. TDOA consistency (weighted variance of emission-time estimates)
    if (hits.length > 1 && group.cls !== 'periodic') { // periodic = envelope rhythm, no sharp onset
      let wsum = 0, tm = 0;
      for (let i = 0; i < hits.length; i++) { const w = 1 / hs[i] ** 2; wsum += w; tm += w * tau[i]; }
      tm /= wsum;
      for (let i = 0; i < hits.length; i++) cost += ((tau[i] - tm) / hs[i]) ** 2;
    }

    // 4. source-level prior
    cost += ((S - s0) / SIGMA_PRIOR) ** 2;

    const l = -0.5 * cost;
    logL[k] = l;
    if (l > maxL) maxL = l;
  }

  let z = 0;
  const post = new Float32Array(grid.n);
  for (let k = 0; k < grid.n; k++) { post[k] = Math.exp(logL[k] - maxL); z += post[k]; }
  let bx = 0, by = 0, bp = 0, mx = 0, my = 0;
  for (let k = 0; k < grid.n; k++) {
    post[k] /= z;
    mx += post[k] * grid.xs[k];
    my += post[k] * grid.ys[k];
    if (post[k] > bp) { bp = post[k]; bx = grid.xs[k]; by = grid.ys[k]; }
  }
  let v = 0;
  for (let k = 0; k < grid.n; k++) v += post[k] * ((grid.xs[k] - mx) ** 2 + (grid.ys[k] - my) ** 2);
  return { post, best: { x: bx, y: by, p: bp }, spread: Math.sqrt(v) };
}

/** Find survivor candidates as local maxima in the accumulated heat map. */
function findPeaks(heat, grid, minFrac = 0.25, maxPeaks = 5) {
  let max = 0, total = 0;
  for (let k = 0; k < grid.n; k++) { if (heat[k] > max) max = heat[k]; total += heat[k]; }
  if (max <= 1e-6) return [];
  const peaks = [];
  const { cols, rows } = grid;
  for (let r = 0; r < rows; r++)
    for (let c = 0; c < cols; c++) {
      const k = r * cols + c, v = heat[k];
      if (v < max * minFrac) continue;
      let isMax = true;
      for (let dr = -2; dr <= 2 && isMax; dr++)
        for (let dc = -2; dc <= 2; dc++) {
          if (!dr && !dc) continue;
          const rr = r + dr, cc = c + dc;
          if (rr < 0 || cc < 0 || rr >= rows || cc >= cols) continue;
          if (heat[rr * cols + cc] > v) { isMax = false; break; }
        }
      if (!isMax) continue;
      // probability mass within 1.5 m radius and weighted centroid
      const rad = Math.ceil(1.5 / grid.cell);
      let mass = 0, sx = 0, sy = 0;
      for (let dr = -rad; dr <= rad; dr++)
        for (let dc = -rad; dc <= rad; dc++) {
          const rr = r + dr, cc = c + dc;
          if (rr < 0 || cc < 0 || rr >= rows || cc >= cols) continue;
          if (dr * dr + dc * dc > rad * rad) continue;
          const kk = rr * cols + cc;
          mass += heat[kk]; sx += heat[kk] * grid.xs[kk]; sy += heat[kk] * grid.ys[kk];
        }
      peaks.push({ x: sx / mass, y: sy / mass, strength: v / max, share: mass / total, energy: mass });
    }
  peaks.sort((a, b) => b.energy - a.energy);
  return peaks.slice(0, maxPeaks);
}

/**
 * Acoustic self-mapping (BeepBeep two-way ranging).
 * arrivals[i][j] = time (s, in node i's OWN audio clock) at which node i heard node j's chirp.
 * Distance needs no clock sync:  d_ij = c/2 * ((a_i[j]-a_i[i]) - (a_j[j]-a_j[i]))
 */
function rangingDistances(ids, arrivals) {
  const D = [];
  for (let i = 0; i < ids.length; i++) {
    D.push([]);
    for (let j = 0; j < ids.length; j++) {
      if (i === j) { D[i].push(0); continue; }
      const ai = arrivals[ids[i]], aj = arrivals[ids[j]];
      const v = ai && aj && [ai[ids[j]], ai[ids[i]], aj[ids[j]], aj[ids[i]]];
      if (!v || v.some((t) => t == null)) { D[i].push(null); continue; }
      const d = (C / 2) * ((v[0] - v[1]) - (v[2] - v[3])) + SELF_D;
      D[i].push(Math.max(0.05, d));
    }
  }
  // symmetrise
  for (let i = 0; i < ids.length; i++)
    for (let j = i + 1; j < ids.length; j++) {
      const a = D[i][j], b = D[j][i];
      const m = a != null && b != null ? (a + b) / 2 : a ?? b;
      D[i][j] = D[j][i] = m;
    }
  return D;
}

/** Classical MDS -> 2-D, then anchor node0 at origin & node1 on +x. Missing distances filled by mean. */
function mds2d(D) {
  const n = D.length;
  if (n < 2) return { points: [{ x: 0, y: 0 }], stress: 0 };
  let s = 0, c = 0;
  for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) if (i !== j && D[i][j] != null) { s += D[i][j]; c++; }
  const fill = c ? s / c : 3;
  const D2 = D.map((row, i) => row.map((d, j) => (i === j ? 0 : (d ?? fill) ** 2)));
  // double centring
  const rm = D2.map((r) => r.reduce((a, b) => a + b, 0) / n);
  const gm = rm.reduce((a, b) => a + b, 0) / n;
  const B = D2.map((r, i) => r.map((v, j) => -0.5 * (v - rm[i] - rm[j] + gm)));
  const eig = (M, deflate) => {
    let v = Array.from({ length: n }, (_, i) => Math.sin(i + 1.3) + 1.1);
    let lam = 0;
    for (let it = 0; it < 300; it++) {
      let w = M.map((r) => r.reduce((a, x, j) => a + x * v[j], 0));
      if (deflate) { const d = deflate.v.reduce((a, x, i) => a + x * w[i], 0); w = w.map((x, i) => x - d * deflate.v[i]); }
      const nrm = Math.hypot(...w) || 1;
      lam = w.reduce((a, x, i) => a + x * v[i], 0);
      v = w.map((x) => x / nrm);
    }
    return { v, lam };
  };
  const e1 = eig(B);
  const B2 = B.map((r, i) => r.map((x, j) => x - e1.lam * e1.v[i] * e1.v[j]));
  const e2 = eig(B2);
  let P = e1.v.map((x, i) => ({ x: x * Math.sqrt(Math.max(0, e1.lam)), y: e2.v[i] * Math.sqrt(Math.max(0, e2.lam)) }));
  // anchor
  const o = P[0];
  P = P.map((p) => ({ x: p.x - o.x, y: p.y - o.y }));
  const ang = Math.atan2(P[1].y, P[1].x);
  const ca = Math.cos(-ang), sa = Math.sin(-ang);
  P = P.map((p) => ({ x: p.x * ca - p.y * sa, y: p.x * sa + p.y * ca }));
  if (n > 2 && P[2].y < 0) P = P.map((p) => ({ x: p.x, y: -p.y }));
  // stress
  let st = 0, sn = 0;
  for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) if (D[i][j] != null) {
    const e = Math.hypot(P[i].x - P[j].x, P[i].y - P[j].y);
    st += (e - D[i][j]) ** 2; sn += D[i][j] ** 2;
  }
  return { points: P, stress: sn ? Math.sqrt(st / sn) : 0 };
}

module.exports = { C, DETECT_MARGIN, makeGrid, localize, findPeaks, pathLoss, rangingDistances, mds2d };
