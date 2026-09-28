// EchoSwarm command console.
import { Link, qs } from './net.js';

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = (v, d = 1) => (v == null ? '--' : v.toFixed(d));
const hhmmss = (t) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;

const COL = { signal: '#ff6a1a', voice: '#b8a4ff', rhythm: '#36c5d6', text: '#ebe8e2', text2: '#a8a49c', text3: '#75726c', line: '#1c1f22', line2: '#2b3035', ok: '#3ecf7a', caution: '#f2b705' };
const CLS_COL = { impact: COL.signal, voice: COL.voice, periodic: COL.rhythm, other: COL.text3 };

const V = {
  state: null, heat: null, heatCanvas: document.createElement('canvas'),
  ripples: [], rays: [], pulses: new Map(), ranges: [], rangesAt: 0,
  sel: null, drag: null, placing: false, hover: null,
  view: { sc: 1, ox: 0, oy: 0 },
};

// ---------------- site bootstrap ----------------
let code = (qs('site') || '').toUpperCase();
if (!code) {
  const r = await fetch('/api/sites', { method: 'POST' }).then((r) => r.json());
  code = r.code;
  history.replaceState(null, '', `/command?site=${code}`);
}
$('#siteCode').textContent = code;
const joinUrl = `${location.origin}/node?site=${code}`;
$('#joinLink').textContent = joinUrl.replace(/^https?:\/\//, '');
$('#joinLink').href = joinUrl;
try {
  const q = qrcode(0, 'M');
  q.addData(joinUrl);
  q.make();
  $('#qr').innerHTML = q.createSvgTag({ cellSize: 4, margin: 0, scalable: true });
} catch {}
document.title = `EchoSwarm ${code}`;

const link = new Link({ type: 'hello', role: 'command', site: code }, onMsg, (up) => {
  const c = $('#conn');
  c.className = `status ${up ? 'live' : 'bad'}`;
  c.textContent = up ? 'Live' : 'Reconnecting';
});
const cmd = (m) => link.send(m);

// ---------------- messages ----------------
function onMsg(m) {
  switch (m.type) {
    case 'state': onState(m); break;
    case 'logs': $('#log').innerHTML = ''; m.entries.forEach(addLog); break;
    case 'log': addLog(m.entry); break;
    case 'hit': V.pulses.set(m.nodeId, { t: performance.now(), cls: m.cls, seismic: m.seismic }); break;
    case 'event': {
      const t = performance.now();
      V.ripples.push({ t, x: m.x, y: m.y, cls: m.cls, seismic: m.seismic, pattern: !!m.pattern, spread: m.spread });
      for (const h of m.hits) V.rays.push({ t, id: h.nodeId, x: m.x, y: m.y, cls: m.cls });
      break;
    }
    case 'mapped': V.ranges = m.pairs; V.rangesAt = performance.now(); break;
  }
}

function onState(s) {
  V.state = s;
  const bin = atob(s.heat);
  const q = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) q[i] = bin.charCodeAt(i);
  V.heat = q;
  paintHeat();
  renderKpis();
  renderCands();
  renderNodes();
  renderMode();
  if (document.activeElement !== $('#bw') && document.activeElement !== $('#bh')) { $('#bw').value = s.bounds.w; $('#bh').value = s.bounds.h; }
}

// ---------------- heat map texture ----------------
const RAMP = (() => {
  const stops = [[0, [27, 13, 5]], [0.3, [122, 42, 6]], [0.62, [255, 106, 26]], [0.85, [255, 208, 138]], [1, [255, 246, 232]]];
  const lut = new Uint8ClampedArray(256 * 4);
  for (let i = 0; i < 256; i++) {
    const v = i / 255;
    let k = 0; while (k < stops.length - 2 && v > stops[k + 1][0]) k++;
    const [a, ca] = stops[k], [b, cb] = stops[k + 1];
    const f = (v - a) / (b - a);
    for (let c = 0; c < 3; c++) lut[i * 4 + c] = ca[c] + (cb[c] - ca[c]) * f;
    lut[i * 4 + 3] = v < 0.04 ? 0 : Math.min(235, 40 + v * 260);
  }
  return lut;
})();

function paintHeat() {
  const { cols, rows } = V.state.grid;
  const c = V.heatCanvas;
  if (c.width !== cols) { c.width = cols; c.height = rows; }
  const g = c.getContext('2d');
  const img = g.createImageData(cols, rows);
  for (let k = 0; k < V.heat.length; k++) img.data.set(RAMP.subarray(V.heat[k] * 4, V.heat[k] * 4 + 4), k * 4);
  g.putImageData(img, 0, 0);
}

// ---------------- side panels ----------------
function renderKpis() {
  const s = V.state;
  $('#kNodes').textContent = s.nodes.filter((n) => n.alive).length;
  $('#kEvents').textContent = s.stats.events;
  $('#kCands').textContent = s.candidates.length;
  const top = s.candidates.reduce((a, c) => Math.max(a, c.conf), 0);
  $('#kTop').textContent = s.candidates.length ? `${Math.round(top * 100)}%` : '--';
}

function renderMode() {
  const s = V.state, b = $('#modeBadge');
  const silLeft = Math.ceil((s.silenceUntil - s.serverTime) / 1000);
  if (silLeft > 0) { b.hidden = false; b.className = 'mode'; b.textContent = `Silence ${silLeft}s`; }
  else if (s.ranging && s.ranging.phase === 'chirping') { b.hidden = false; b.className = 'mode ranging'; b.textContent = 'Auto-mapping'; }
  else b.hidden = true;
  $('#sCrew').textContent = s.crew ? 'Crew noise on' : 'Crew noise off';
  $('#sCrew').classList.toggle('on', s.crew);
  $('#sCrew').setAttribute('aria-pressed', s.crew);
}

function keyed(container, items, key, create, update) {
  const existing = new Map([...container.children].map((el) => [el.dataset.key, el]));
  items.forEach((it, i) => {
    const k = String(key(it));
    let el = existing.get(k);
    if (!el) { el = create(it); el.dataset.key = k; }
    existing.delete(k);
    update(el, it);
    if (container.children[i] !== el) container.insertBefore(el, container.children[i] || null);
  });
  for (const el of existing.values()) el.remove();
}

function renderCands() {
  const s = V.state;
  const list = [...s.candidates].sort((a, b) => b.conf - a.conf);
  $('#candsEmpty').hidden = list.length > 0;
  keyed($('#cands'), list, (c) => c.id, (c) => {
    const li = document.createElement('li');
    li.className = 'cand';
    li.innerHTML = `<div class="row1"><span class="id"></span><span class="pos"></span><span class="pct"></span></div>
      <div class="bar-c"><i></i></div><div class="tags"></div>
      <div class="act"><button class="btn" data-probe><svg class="icon"><use href="#i-call"/></svg>Knock-back probe</button></div>`;
    li.addEventListener('click', (e) => {
      if (e.target.closest('[data-probe]')) { cmd({ type: 'probe', candId: c.id, lang: $('#lang').value }); return; }
      V.sel = V.sel === c.id ? null : c.id;
    });
    return li;
  }, (el, c) => {
    el.classList.toggle('sel', V.sel === c.id);
    el.querySelector('.id').textContent = `C-${String(c.id).padStart(2, '0')}`;
    el.querySelector('.pos').textContent = `${fmt(c.x)}, ${fmt(c.y)} m  ±${fmt(c.radius)}`;
    el.querySelector('.pct').textContent = `${Math.round(c.conf * 100)}%`;
    el.querySelector('.bar-c i').style.width = `${c.conf * 100}%`;
    const tags = [];
    if (c.responsive === true) tags.push('<span class="tag ok">RESPONDED</span>');
    if (c.responsive === false) tags.push('<span class="tag warn">NO REPLY</span>');
    if (c.pattern) tags.push('<span class="tag hot">KNOCK PATTERN</span>');
    if (c.seismic) tags.push(`<span class="tag">THROUGH RUBBLE ×${c.seismic}</span>`);
    const cl = c.classes || {};
    if (cl.voice) tags.push(`<span class="tag">VOICE ×${cl.voice}</span>`);
    if (cl.periodic) tags.push('<span class="tag">RHYTHMIC</span>');
    const ago = c.last ? Math.max(0, Math.round((V.state.serverTime - c.last) / 1000)) : null;
    tags.push(`<span class="tag">${c.events} EVT${ago != null ? ` · ${ago}s AGO` : ''}</span>`);
    const html = tags.join('');
    const t = el.querySelector('.tags');
    if (t.innerHTML !== html) t.innerHTML = html;
  });
  if (V.sel && !list.some((c) => c.id === V.sel)) V.sel = null;
}

function renderNodes() {
  const s = V.state;
  const list = [...s.nodes].sort((a, b) => (b.alive - a.alive) || a.name.localeCompare(b.name));
  $('#nodesEmpty').hidden = list.length > 0;
  const unplaced = list.filter((n) => !n.placed && n.alive).length;
  $('#swarmNote').textContent = unplaced ? `${unplaced} not on map` : list.length ? `${list.filter((n) => n.alive).length} live` : '';
  keyed($('#nodes'), list, (n) => n.id, (n) => {
    const li = document.createElement('li');
    li.className = 'node';
    li.innerHTML = `<span class="sw"></span><div><div class="nm"><span class="t"></span><span class="tg"></span></div><div class="meta"></div></div>
      <div style="display:flex;gap:6px;align-items:center"><span class="lvl"><i></i></span><button class="btn quiet" data-ping title="Make this phone beep and flash">Ping</button></div>`;
    li.querySelector('[data-ping]').addEventListener('click', () => cmd({ type: 'identify', id: n.id }));
    return li;
  }, (el, n) => {
    el.classList.toggle('off', !n.alive);
    el.querySelector('.sw').style.background = n.color;
    el.querySelector('.t').textContent = n.name;
    const tg = !n.alive ? 'OFFLINE' : !n.placed ? 'NOT PLACED' : n.virtual ? 'SIM' : '';
    const tge = el.querySelector('.tg');
    tge.className = `tg${tg ? ' tag' : ''}${tg === 'NOT PLACED' ? ' warn' : ''}`;
    tge.textContent = tg;
    el.querySelector('.meta').textContent = `floor ${Math.round(n.floor)} dB · ${n.rtt != null ? `sync ${Math.round(n.rtt / 2)} ms · ` : ''}${n.events} det${n.motion ? ' · vib' : ''}`;
    el.querySelector('.lvl i').style.width = `${Math.max(0, Math.min(1, (n.level - n.floor) / 30)) * 100}%`;
    el.querySelector('[data-ping]').hidden = n.virtual;
  });
}

function addLog(e) {
  const li = document.createElement('li');
  li.className = e.level;
  li.innerHTML = `<time>${hhmmss(e.t)}</time><span></span>`;
  li.lastChild.textContent = e.text;
  const log = $('#log');
  log.prepend(li);
  while (log.children.length > 150) log.lastChild.remove();
}

// ---------------- map rendering ----------------
const cv = $('#map');
const g = cv.getContext('2d');
const P = (x, y) => [V.view.ox + x * V.view.sc, V.view.oy + y * V.view.sc];
const M = (px, py) => [(px - V.view.ox) / V.view.sc, (py - V.view.oy) / V.view.sc];

function layout() {
  const dpr = Math.min(2, devicePixelRatio || 1);
  const w = cv.clientWidth, h = cv.clientHeight;
  if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) { cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr); }
  g.setTransform(dpr, 0, 0, dpr, 0, 0);
  const b = V.state ? V.state.bounds : { w: 24, h: 16 };
  const pad = 44;
  const sc = Math.min((w - pad * 2) / b.w, (h - pad * 2 - 30) / b.h);
  V.view = { sc, ox: (w - b.w * sc) / 2, oy: (h - 30 - b.h * sc) / 2 + 4, w, h };
}

function frame() {
  layout();
  const { w, h, sc } = V.view;
  const t = performance.now();
  g.clearRect(0, 0, w, h);
  if (!V.state) { requestAnimationFrame(frame); return; }
  const s = V.state, b = s.bounds;
  const [x0, y0] = P(0, 0), [x1, y1] = P(b.w, b.h);

  // grid
  g.lineWidth = 1;
  for (let x = 0; x <= b.w; x++) {
    g.strokeStyle = x % 5 === 0 ? COL.line2 : COL.line;
    g.beginPath(); g.moveTo(Math.round(P(x, 0)[0]) + 0.5, y0); g.lineTo(Math.round(P(x, 0)[0]) + 0.5, y1); g.stroke();
  }
  for (let y = 0; y <= b.h; y++) {
    g.strokeStyle = y % 5 === 0 ? COL.line2 : COL.line;
    g.beginPath(); g.moveTo(x0, Math.round(P(0, y)[1]) + 0.5); g.lineTo(x1, Math.round(P(0, y)[1]) + 0.5); g.stroke();
  }
  g.fillStyle = COL.text3; g.font = '500 11px "IBM Plex Mono", monospace';
  g.textAlign = 'center'; g.textBaseline = 'top';
  for (let x = 0; x <= b.w; x += 5) g.fillText(`${x}`, P(x, 0)[0], y1 + 8);
  g.textAlign = 'right'; g.textBaseline = 'middle';
  for (let y = 0; y <= b.h; y += 5) g.fillText(`${y}`, x0 - 8, P(0, y)[1]);
  g.textAlign = 'left'; g.textBaseline = 'top';
  g.fillText('m', x1 + 6, y1 + 8);

  // heat
  if (V.heat) {
    g.imageSmoothingEnabled = true;
    g.imageSmoothingQuality = 'high';
    g.drawImage(V.heatCanvas, x0, y0, x1 - x0, y1 - y0);
  }
  g.strokeStyle = COL.line2; g.strokeRect(x0 + 0.5, y0 + 0.5, x1 - x0, y1 - y0);

  // mode frame
  const silent = s.silenceUntil > s.serverTime;
  if (silent || (s.ranging && s.ranging.phase === 'chirping')) {
    g.strokeStyle = silent ? COL.rhythm : COL.text; g.lineWidth = 3;
    g.strokeRect(x0 - 6, y0 - 6, x1 - x0 + 12, y1 - y0 + 12); g.lineWidth = 1;
  }

  const nodeById = new Map(s.nodes.map((n) => [n.id, n]));

  // auto-map ranging lines
  const ra = (t - V.rangesAt) / 9000;
  if (V.ranges.length && ra < 1) {
    g.globalAlpha = 1 - ra;
    g.strokeStyle = COL.text2; g.setLineDash([2, 4]);
    g.font = '500 10px "IBM Plex Mono", monospace'; g.textAlign = 'center'; g.textBaseline = 'middle';
    for (const r of V.ranges) {
      const a = nodeById.get(r.a), c = nodeById.get(r.b);
      if (!a || !c || r.d == null) continue;
      const [ax, ay] = P(a.x, a.y), [cx, cy] = P(c.x, c.y);
      g.beginPath(); g.moveTo(ax, ay); g.lineTo(cx, cy); g.stroke();
      g.fillStyle = '#08090a'; g.fillRect((ax + cx) / 2 - 18, (ay + cy) / 2 - 7, 36, 14);
      g.fillStyle = COL.text2; g.fillText(`${r.d.toFixed(1)}`, (ax + cx) / 2, (ay + cy) / 2);
    }
    g.setLineDash([]); g.globalAlpha = 1;
  }

  // rays: which phones heard this sound
  V.rays = V.rays.filter((r) => t - r.t < 1400);
  for (const r of V.rays) {
    const n = nodeById.get(r.id);
    if (!n || !n.placed) continue;
    const p = (t - r.t) / 1400;
    const [ax, ay] = P(n.x, n.y), [bx, by] = P(r.x, r.y);
    g.strokeStyle = CLS_COL[r.cls] || COL.text3; g.globalAlpha = 0.55 * (1 - p); g.lineWidth = 1;
    g.beginPath(); g.moveTo(ax, ay); g.lineTo(bx, by); g.stroke();
  }
  g.globalAlpha = 1;

  // ripples at estimated source
  V.ripples = V.ripples.filter((r) => t - r.t < 1800);
  for (const r of V.ripples) {
    const p = (t - r.t) / 1800;
    const [px, py] = P(r.x, r.y);
    g.strokeStyle = CLS_COL[r.cls] || COL.text3; g.globalAlpha = 1 - p; g.lineWidth = r.pattern ? 2.5 : 1.5;
    if (r.seismic) g.setLineDash([3, 3]);
    g.beginPath(); g.arc(px, py, 4 + p * Math.max(18, r.spread * sc), 0, Math.PI * 2); g.stroke();
    g.setLineDash([]);
  }
  g.globalAlpha = 1;

  // hidden survivors (simulator ground truth)
  if ($('#sReveal').checked) {
    for (const sv of s.survivors) {
      const [px, py] = P(sv.x, sv.y);
      g.strokeStyle = COL.ok; g.lineWidth = 2;
      g.beginPath(); g.moveTo(px - 6, py - 6); g.lineTo(px + 6, py + 6); g.moveTo(px + 6, py - 6); g.lineTo(px - 6, py + 6); g.stroke();
      g.fillStyle = COL.ok; g.font = '500 11px "IBM Plex Mono", monospace'; g.textAlign = 'left'; g.textBaseline = 'middle';
      g.fillText('TRUTH', px + 10, py);
    }
  }

  // candidates
  for (const c of s.candidates) {
    const [px, py] = P(c.x, c.y);
    const r = Math.max(12, c.radius * sc);
    const sel = V.sel === c.id;
    const pulse = reduceMotion ? 0 : (t / 1400) % 1;
    g.strokeStyle = COL.text; g.lineWidth = sel ? 2 : 1.25;
    g.beginPath(); g.arc(px, py, r, 0, Math.PI * 2); g.stroke();
    if (!reduceMotion) { g.globalAlpha = 1 - pulse; g.beginPath(); g.arc(px, py, r + pulse * 16, 0, Math.PI * 2); g.stroke(); g.globalAlpha = 1; }
    // crosshair ticks
    g.beginPath();
    [[1, 0], [-1, 0], [0, 1], [0, -1]].forEach(([dx, dy]) => { g.moveTo(px + dx * (r - 5), py + dy * (r - 5)); g.lineTo(px + dx * (r + 7), py + dy * (r + 7)); });
    g.stroke();
    g.fillStyle = COL.text; g.fillRect(px - 2, py - 2, 4, 4);
    // label plate
    const label = `C-${String(c.id).padStart(2, '0')}  ${Math.round(c.conf * 100)}%`;
    g.font = '600 12px "IBM Plex Mono", monospace';
    const tw = g.measureText(label).width + 14;
    const lx = px + r + 8, ly = py - r - 4;
    g.fillStyle = c.responsive ? COL.ok : COL.signal;
    g.fillRect(lx, ly - 10, tw, 20);
    g.fillStyle = '#140800'; g.textAlign = 'left'; g.textBaseline = 'middle';
    g.fillText(label, lx + 7, ly);
    if (c.pattern || c.responsive) {
      g.font = '500 10px "IBM Plex Mono", monospace'; g.fillStyle = COL.text;
      g.fillText(c.responsive ? 'RESPONDED TO PROBE' : 'KNOCK PATTERN', lx, ly + 18);
    }
  }

  // nodes
  for (const n of s.nodes) {
    const [px, py] = P(n.x, n.y);
    const pulse = V.pulses.get(n.id);
    if (pulse && t - pulse.t < 900) {
      const p = (t - pulse.t) / 900;
      g.strokeStyle = CLS_COL[pulse.cls] || COL.text3; g.globalAlpha = 1 - p; g.lineWidth = 1.5;
      g.beginPath(); g.arc(px, py, 8 + p * 22, 0, Math.PI * 2); g.stroke(); g.globalAlpha = 1;
    }
    const size = 12;
    g.globalAlpha = n.alive ? 1 : 0.4;
    if (n.placed) {
      g.fillStyle = n.color; g.fillRect(px - size / 2, py - size / 2, size, size);
      g.strokeStyle = '#08090a'; g.lineWidth = 2; g.strokeRect(px - size / 2, py - size / 2, size, size);
    } else {
      g.setLineDash([2, 2]); g.strokeStyle = n.color; g.lineWidth = 1.5;
      g.strokeRect(px - size / 2, py - size / 2, size, size); g.setLineDash([]);
    }
    g.fillStyle = n.placed ? COL.text : COL.text2;
    g.font = '500 11px "IBM Plex Sans", sans-serif'; g.textAlign = 'center'; g.textBaseline = 'top';
    g.fillText(n.name, px, py + 10);
    g.globalAlpha = 1;
  }
  const unplaced = s.nodes.filter((n) => !n.placed && n.alive);
  if (unplaced.length) {
    g.fillStyle = COL.caution; g.font = '500 11px "IBM Plex Mono", monospace'; g.textAlign = 'left'; g.textBaseline = 'bottom';
    g.fillText('NOT PLACED: drag each phone to where it lies, or run Auto-map', x0, P(0, b.h - 1.6)[1]);
  }

  requestAnimationFrame(frame);
}
requestAnimationFrame(frame);

// ---------------- map interaction ----------------
function nodeAt(px, py) {
  if (!V.state) return null;
  let best = null, bd = 16;
  for (const n of V.state.nodes) {
    const [x, y] = P(n.x, n.y);
    const d = Math.hypot(x - px, y - py);
    if (d < bd) { bd = d; best = n; }
  }
  return best;
}
function candAt(px, py) {
  if (!V.state) return null;
  return V.state.candidates.find((c) => { const [x, y] = P(c.x, c.y); return Math.hypot(x - px, y - py) < Math.max(16, c.radius * V.view.sc); });
}
const local = (e) => { const r = cv.getBoundingClientRect(); return [e.clientX - r.left, e.clientY - r.top]; };

cv.addEventListener('pointerdown', (e) => {
  const [px, py] = local(e);
  if (V.placing) {
    const [x, y] = M(px, py);
    cmd({ type: 'sim', action: 'survivor', x, y, mode: $('#sMode').value });
    setPlacing(false);
    return;
  }
  const n = nodeAt(px, py);
  if (n) { V.drag = n; cv.setPointerCapture(e.pointerId); return; }
  const c = candAt(px, py);
  V.sel = c ? (V.sel === c.id ? null : c.id) : null;
});
cv.addEventListener('pointermove', (e) => {
  const [px, py] = local(e);
  const [x, y] = M(px, py);
  const b = V.state ? V.state.bounds : { w: 0, h: 0 };
  $('#coord').textContent = x >= 0 && y >= 0 && x <= b.w && y <= b.h ? `x ${x.toFixed(1)}  y ${y.toFixed(1)} m` : '';
  if (V.drag) { V.drag.x = Math.max(0, Math.min(b.w, x)); V.drag.y = Math.max(0, Math.min(b.h, y)); V.drag.placed = true; }
  cv.style.cursor = V.placing ? 'crosshair' : V.drag ? 'grabbing' : nodeAt(px, py) ? 'grab' : candAt(px, py) ? 'pointer' : 'default';
});
cv.addEventListener('pointerup', () => {
  if (V.drag) { cmd({ type: 'placeNode', id: V.drag.id, x: V.drag.x, y: V.drag.y }); V.drag = null; }
});

function setPlacing(on) {
  V.placing = on;
  const hint = $('#mapHint');
  hint.hidden = !on;
  hint.textContent = 'Click the map to hide a survivor there. Esc to cancel.';
  $('#sPlace').classList.toggle('on', on);
}

// ---------------- controls ----------------
$('#bSilence').onclick = () => cmd({ type: 'silence', sec: 20 });
$('#bMap').onclick = () => cmd({ type: 'autoMap' });
$('#bReset').onclick = () => cmd({ type: 'resetHeat' });
$('#bReport').onclick = openReport;
const sendBounds = () => cmd({ type: 'bounds', w: +$('#bw').value, h: +$('#bh').value });
$('#bw').onchange = sendBounds;
$('#bh').onchange = sendBounds;
$('#sNodes').onclick = () => cmd({ type: 'sim', action: 'nodes', count: 6 });
$('#sCrew').onclick = () => cmd({ type: 'sim', action: 'crew' });
$('#sPlace').onclick = () => setPlacing(!V.placing);
$('#sClear').onclick = () => cmd({ type: 'sim', action: 'clear' });
addEventListener('keydown', (e) => {
  if (e.target.matches('input, select, textarea')) return;
  if (e.key === 'Escape') { setPlacing(false); V.sel = null; }
  if (e.key === 's' || e.key === 'S') cmd({ type: 'silence', sec: 20 });
  if (e.key === 'm' || e.key === 'M') cmd({ type: 'autoMap' });
});

// ---------------- rescue report ----------------
function openReport() {
  const s = V.state;
  if (!s) return;
  const img = cv.toDataURL('image/png');
  const cands = [...s.candidates].sort((a, b) => (b.responsive === true) - (a.responsive === true) || b.conf - a.conf);
  const logs = [...document.querySelectorAll('#log li')].slice(0, 60).map((li) => `<tr><td>${esc(li.querySelector('time').textContent)}</td><td>${esc(li.lastChild.textContent)}</td></tr>`).join('');
  const rows = cands.map((c, i) => `<tr><td>${i + 1}</td><td><b>C-${String(c.id).padStart(2, '0')}</b></td><td>${fmt(c.x)}, ${fmt(c.y)}</td><td>±${fmt(c.radius)} m</td><td><b>${Math.round(c.conf * 100)}%</b></td>
    <td>${[c.responsive === true ? 'Responded to probe' : c.responsive === false ? 'No reply to probe' : '', c.pattern ? 'Deliberate knock pattern' : '', c.seismic ? `${c.seismic} structure-borne` : '', `${c.events} detections`].filter(Boolean).join('; ')}</td></tr>`).join('');
  const nodes = s.nodes.map((n) => `<tr><td>${esc(n.name)}</td><td>${n.placed ? `${fmt(n.x)}, ${fmt(n.y)}` : 'not placed'}</td><td>${n.alive ? 'live' : 'offline'}${n.virtual ? ' (sim)' : ''}</td><td>${Math.round(n.floor)} dB</td><td>${n.events}</td></tr>`).join('');
  const w = window.open('', '_blank');
  w.document.write(`<!doctype html><html><head><meta charset="utf-8"><title>EchoSwarm rescue report ${esc(s.code)}</title>
  <style>body{font:14px/1.5 'IBM Plex Sans',system-ui,sans-serif;color:#111;margin:32px auto;max-width:900px;padding:0 20px}
  h1{font-size:22px;margin:0}h2{font-size:15px;margin:28px 0 8px;text-transform:uppercase;letter-spacing:.08em}
  .meta{color:#555;font-family:'IBM Plex Mono',monospace;font-size:12px;margin:4px 0 16px}
  table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid #ddd;vertical-align:top}
  th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#555}img{width:100%;border:1px solid #ccc;background:#08090a}
  .note{color:#555;font-size:12px}button{font:inherit;padding:8px 14px;margin-top:12px}@media print{button{display:none}}</style></head><body>
  <h1>EchoSwarm rescue report · site ${esc(s.code)}</h1>
  <div class="meta">Generated ${new Date().toLocaleString()} · ${s.nodes.filter((n) => n.alive).length} live sensor nodes · ${s.stats.events} detections · site ${s.bounds.w} × ${s.bounds.h} m</div>
  <img src="${img}" alt="Site map">
  <h2>Dig priority</h2>
  ${cands.length ? `<table><tr><th>#</th><th>Candidate</th><th>Position (m)</th><th>Uncertainty</th><th>Confidence</th><th>Evidence</th></tr>${rows}</table>` : '<p>No survivor candidates at the time of this report.</p>'}
  <p class="note">Positions are in metres from the top-left corner of the site grid. Responders to the knock-back probe come first, then candidates in order of confidence.</p>
  <h2>Sensor nodes</h2><table><tr><th>Node</th><th>Position (m)</th><th>Status</th><th>Noise floor</th><th>Detections</th></tr>${nodes}</table>
  <h2>Timeline</h2><table>${logs}</table>
  <button onclick="print()">Print / save as PDF</button></body></html>`);
  w.document.close();
}
