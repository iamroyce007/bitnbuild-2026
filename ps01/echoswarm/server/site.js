// A rescue "site": one collapse zone, its swarm of phone nodes, command consoles,
// the fused survivor-probability map and all automation (silence windows, auto-mapping,
// knock-back probes, tap-pattern detection, simulation).
const { C, DETECT_MARGIN, makeGrid, localize, findPeaks, pathLoss, rangingDistances, mds2d } = require('./fusion');

const CLASS_W = { impact: 1.0, voice: 0.9, periodic: 0.55, other: 0.2 };
const HALF_LIFE_S = 150;
const GROUP_WINDOW_S = 0.16; // ~55 m of acoustic path; beyond that it's a different sound
const GROUP_SETTLE_MS = 450;
const ALIVE_MS = 6000;
const COLORS = ['#38bdf8', '#a78bfa', '#f472b6', '#34d399', '#fbbf24', '#fb923c', '#60a5fa', '#e879f9', '#4ade80', '#f87171'];

const gauss = () => { let u = 0, v = 0; while (!u) u = Math.random(); while (!v) v = Math.random(); return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v); };
const send = (ws, msg) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(msg)); };
const now = () => Date.now();

class Site {
  constructor(code) {
    this.code = code;
    this.created = now();
    this.bounds = { w: 24, h: 16 };
    this.cell = 0.4;
    this.grid = makeGrid(this.bounds, this.cell);
    this.heat = new Float32Array(this.grid.n);
    this.nodes = new Map();
    this.commands = new Set();
    this.candidates = [];
    this.nextCand = 1;
    this.pending = [];
    this.history = [];
    this.log = [];
    this.silenceUntil = 0;
    this.ranging = null;
    this.probes = new Map();
    this.sim = { survivors: [], crew: false, nextCrew: 0 };
    this.stats = { events: 0, groups: 0 };
    this.lastState = 0;
    this.addLog('info', `Site ${code} opened. Scan the QR code on any phone to add a sensor node.`);
    this.timer = setInterval(() => this.step(), 250);
  }

  destroy() { clearInterval(this.timer); }

  addLog(level, text, extra) {
    const e = { t: now(), level, text, ...extra };
    this.log.push(e);
    if (this.log.length > 300) this.log.shift();
    for (const ws of this.commands) send(ws, { type: 'log', entry: e });
  }

  // ---------- node management ----------
  attachNode(ws, hello) {
    let node = hello.clientId && this.nodes.get(hello.clientId);
    const idx = this.nodes.size;
    if (!node) {
      node = {
        id: hello.clientId || `n${Math.random().toString(36).slice(2, 8)}`,
        name: (hello.name || `Node-${idx + 1}`).slice(0, 24),
        color: COLORS[idx % COLORS.length],
        virtual: false,
        placed: false,
        ...this.parkingSpot(idx),
        floor: -60, level: -90, gain: 0,
        syncSigma: 0.03, rtt: null,
        events: 0, motion: false, device: (hello.device || '').slice(0, 60),
      };
      this.nodes.set(node.id, node);
      this.addLog('good', `${node.name} joined the swarm (${node.device || 'phone'}). Drag it onto the map or run Auto-Map.`);
    } else {
      if (hello.name) node.name = hello.name.slice(0, 24);
      this.addLog('info', `${node.name} reconnected.`);
    }
    node.ws = ws;
    node.lastSeen = now();
    send(ws, { type: 'welcome', id: node.id, name: node.name, color: node.color, site: this.code, silenceUntil: this.silenceUntil, placed: node.placed });
    return node;
  }

  parkingSpot(idx) {
    // unplaced nodes wait in a "tray" along the bottom edge of the map
    return { x: 1 + (idx % 12) * 1.8, y: this.bounds.h - 0.8 };
  }

  detachNode(node) {
    node.ws = null;
    this.addLog('warn', `${node.name} went offline.`);
  }

  aliveNodes() {
    const t = now();
    return [...this.nodes.values()].filter((n) => n.virtual || (n.ws && t - n.lastSeen < ALIVE_MS));
  }

  // ---------- messages ----------
  onNodeMessage(node, m) {
    node.lastSeen = now();
    switch (m.type) {
      case 'status':
        node.floor = m.floor; node.level = m.level; node.motion = !!m.motion; node.battery = m.battery;
        if (m.rtt != null) { node.rtt = m.rtt; node.syncSigma = Math.max(0.006, Math.min(0.08, m.rtt / 1000 / 2 + 0.006)); }
        break;
      case 'event':
        this.ingest(node, { t: m.t / 1000, level: m.level, cls: m.cls, conf: m.conf, seismic: !!m.seismic, dur: m.dur, floor: m.floor });
        break;
      case 'rangingResult':
        this.onRangingResult(node, m);
        break;
      case 'probeResult':
        this.onProbeResult(node, m);
        break;
    }
  }

  onCommandMessage(ws, m) {
    switch (m.type) {
      case 'placeNode': {
        const n = this.nodes.get(m.id);
        if (!n) return;
        n.x = clamp(m.x, 0, this.bounds.w); n.y = clamp(m.y, 0, this.bounds.h);
        if (n.virtual) n.truePos = { x: n.x, y: n.y };
        if (!n.placed) this.addLog('info', `${n.name} placed at (${n.x.toFixed(1)}, ${n.y.toFixed(1)}) m.`);
        n.placed = true;
        send(n.ws, { type: 'placed', x: n.x, y: n.y });
        break;
      }
      case 'renameNode': { const n = this.nodes.get(m.id); if (n) n.name = String(m.name).slice(0, 24); break; }
      case 'removeNode': { const n = this.nodes.get(m.id); if (n) { send(n.ws, { type: 'removed' }); this.nodes.delete(m.id); } break; }
      case 'identify': { const n = this.nodes.get(m.id); send(n && n.ws, { type: 'identify' }); break; }
      case 'silence': this.startSilence(m.sec || 20); break;
      case 'autoMap': this.startRanging(); break;
      case 'probe': this.startProbe(m.candId, m.lang || 'en'); break;
      case 'resetHeat': this.heat.fill(0); this.history = []; this.candidates = []; this.addLog('info', 'Evidence map cleared.'); break;
      case 'bounds': {
        const w = clamp(+m.w || 24, 6, 120), h = clamp(+m.h || 16, 6, 120);
        this.bounds = { w, h };
        this.cell = Math.max(0.3, Math.max(w, h) / 70);
        this.grid = makeGrid(this.bounds, this.cell);
        this.heat = new Float32Array(this.grid.n);
        this.candidates = [];
        for (const n of this.nodes.values()) { n.x = clamp(n.x, 0, w); n.y = clamp(n.y, 0, h); }
        this.addLog('info', `Site area set to ${w} × ${h} m.`);
        break;
      }
      case 'sim': this.onSim(m); break;
    }
  }

  // ---------- detection → grouping → fusion ----------
  ingest(node, ev) {
    node.events++;
    this.stats.events++;
    for (const ws of this.commands) send(ws, { type: 'hit', nodeId: node.id, level: ev.level, cls: ev.cls, seismic: ev.seismic });
    let g = this.pending.find((p) => Math.abs(p.t0 - ev.t) < GROUP_WINDOW_S && !p.hits.some((h) => h.nodeId === node.id));
    if (!g) {
      g = { t0: ev.t, hits: [], created: now() };
      this.pending.push(g);
      setTimeout(() => this.finalize(g), GROUP_SETTLE_MS);
    }
    g.hits.push({ nodeId: node.id, ...ev });
  }

  finalize(g) {
    this.pending = this.pending.filter((p) => p !== g);
    const alive = this.aliveNodes().filter((n) => n.placed);
    const placedIds = new Set(alive.map((n) => n.id));
    const hits = g.hits.filter((h) => placedIds.has(h.nodeId));
    if (!hits.length) return;
    // class vote weighted by confidence
    const votes = {};
    for (const h of hits) votes[h.cls] = (votes[h.cls] || 0) + (h.conf || 0.5);
    const cls = Object.entries(votes).sort((a, b) => b[1] - a[1])[0][0];
    const seismic = hits.some((h) => h.seismic);
    const conf = hits.reduce((a, h) => a + (h.conf || 0.5), 0) / hits.length;
    const silent = now() < this.silenceUntil;

    const res = localize({ cls, hits }, alive.map((n) => ({ id: n.id, x: n.x, y: n.y, floor: n.floor, gain: n.gain, syncSigma: n.syncSigma })), this.grid);
    if (!res) return;
    this.stats.groups++;

    let w = (CLASS_W[cls] ?? 0.2) * (0.4 + 0.6 * conf);
    if (seismic) w *= 1.5; // structure-borne: came through the rubble, not the air
    if (silent) w *= 1.3; // crew is quiet: what we hear is more likely a survivor
    if (!seismic && cls === 'other') w *= 0.5;

    const rec = { t: g.t0, x: res.best.x, y: res.best.y, spread: res.spread, cls, seismic, n: hits.length, w };
    this.history.push(rec);
    if (this.history.length > 400) this.history.shift();

    // deliberate tap-pattern detector (SOS-style knocking = conscious survivor)
    const pattern = cls === 'impact' ? this.detectPattern(rec) : null;
    if (pattern) w *= 1.8;
    rec.pattern = !!pattern;

    for (let k = 0; k < this.grid.n; k++) this.heat[k] += w * res.post[k];

    const out = { type: 'event', x: rec.x, y: rec.y, spread: rec.spread, cls, seismic, pattern, hits: hits.map((h) => ({ nodeId: h.nodeId, level: h.level })), w };
    for (const ws of this.commands) send(ws, out);
    if (pattern && (!this.lastPatternLog || now() - this.lastPatternLog > 6000)) {
      this.lastPatternLog = now();
      this.addLog('alert', `Rhythmic knocking detected near (${rec.x.toFixed(1)}, ${rec.y.toFixed(1)}) m. ${pattern}. This looks like deliberate signalling.`, { x: rec.x, y: rec.y });
    }
  }

  detectPattern(rec) {
    const near = this.history.filter((h) => h.cls === 'impact' && rec.t - h.t < 10 && Math.hypot(h.x - rec.x, h.y - rec.y) < 3.5);
    if (near.length < 3) return null;
    const ts = near.map((h) => h.t).sort((a, b) => a - b);
    const iv = ts.slice(1).map((t, i) => t - ts[i]).filter((d) => d > 0.12);
    if (iv.length < 2) return null;
    const short = iv.filter((d) => d < 1.2);
    const long = iv.filter((d) => d >= 1.2);
    const mean = (a) => a.reduce((x, y) => x + y, 0) / a.length;
    const cv = (a) => { const m = mean(a); return Math.sqrt(mean(a.map((x) => (x - m) ** 2))) / m; };
    if (short.length >= 2 && cv(short) < 0.35) {
      return long.length ? `${near.length} knocks in groups (≈${mean(short).toFixed(2)} s apart)` : `${near.length} evenly spaced knocks (≈${mean(short).toFixed(2)} s apart)`;
    }
    if (iv.length >= 3 && cv(iv) < 0.3) return `${near.length} knocks at a steady ${mean(iv).toFixed(1)} s rhythm`;
    return null;
  }

  // ---------- periodic loop ----------
  step() {
    const decay = Math.pow(0.5, 0.25 / HALF_LIFE_S);
    for (let k = 0; k < this.heat.length; k++) this.heat[k] *= decay;
    this.simStep();
    this.updateCandidates();
    for (const n of this.nodes.values()) if (!n.virtual && !n.ws && now() - n.lastSeen > 5 * 60e3) this.nodes.delete(n.id);
    if (now() - this.lastState > 450) { this.lastState = now(); this.broadcastState(); }
  }

  updateCandidates() {
    const peaks = findPeaks(this.heat, this.grid, 0.3, 5).filter((p) => p.energy > 0.35);
    const next = [];
    for (const p of peaks) {
      let c = this.candidates.find((c) => Math.hypot(c.x - p.x, c.y - p.y) < 2.2 && !next.includes(c));
      if (!c) {
        c = { id: this.nextCand++, first: now(), responsive: null };
        this.addLog('alert', `New survivor candidate #${c.id} at (${p.x.toFixed(1)}, ${p.y.toFixed(1)}) m.`, { x: p.x, y: p.y });
      }
      c.x = c.x == null ? p.x : c.x * 0.6 + p.x * 0.4;
      c.y = c.y == null ? p.y : c.y * 0.6 + p.y * 0.4;
      c.energy = p.energy;
      c.strength = p.strength;
      const near = this.history.filter((h) => Math.hypot(h.x - c.x, h.y - c.y) < 2.5 && now() / 1000 - h.t < 300);
      c.events = near.length;
      c.pattern = near.some((h) => h.pattern);
      c.seismic = near.filter((h) => h.seismic).length;
      c.classes = near.reduce((a, h) => ((a[h.cls] = (a[h.cls] || 0) + 1), a), {});
      c.last = near.length ? Math.max(...near.map((h) => h.t)) * 1000 : c.last;
      const spreads = near.map((h) => h.spread).sort((a, b) => a - b);
      c.radius = spreads.length ? Math.max(0.6, spreads[Math.floor(spreads.length / 2)] / Math.sqrt(Math.min(spreads.length, 9))) : 2;
      let conf = (1 - Math.exp(-c.energy / 1.6)) * (0.55 + 0.45 * c.strength);
      if (c.pattern) conf = Math.min(0.99, conf + 0.15);
      if (c.responsive) conf = Math.min(0.995, conf + 0.2);
      c.conf = Math.min(0.99, conf);
      next.push(c);
    }
    this.candidates = next;
  }

  broadcastState() {
    if (!this.commands.size) return;
    const max = this.heat.reduce((a, b) => (b > a ? b : a), 0);
    const q = new Uint8Array(this.grid.n);
    if (max > 1e-6) for (let k = 0; k < this.grid.n; k++) q[k] = Math.min(255, Math.round((this.heat[k] / max) * 255));
    const t = now();
    const state = {
      type: 'state',
      code: this.code,
      bounds: this.bounds,
      grid: { cols: this.grid.cols, rows: this.grid.rows, cell: this.grid.cell },
      heat: Buffer.from(q).toString('base64'),
      heatMax: max,
      silenceUntil: this.silenceUntil,
      serverTime: t,
      ranging: this.ranging ? { phase: this.ranging.phase, startAt: this.ranging.startAt, endAt: this.ranging.endAt } : null,
      stats: this.stats,
      nodes: [...this.nodes.values()].map((n) => ({
        id: n.id, name: n.name, color: n.color, x: n.x, y: n.y, placed: n.placed, virtual: n.virtual,
        alive: n.virtual || (!!n.ws && t - n.lastSeen < ALIVE_MS), floor: n.floor, level: n.level,
        rtt: n.rtt, events: n.events, motion: n.motion, device: n.device, battery: n.battery,
      })),
      candidates: this.candidates.map((c) => ({ id: c.id, x: c.x, y: c.y, conf: c.conf, radius: c.radius, events: c.events, pattern: c.pattern, seismic: c.seismic, classes: c.classes, responsive: c.responsive, first: c.first, last: c.last })),
      survivors: this.sim.survivors.map((s) => ({ id: s.id, x: s.x, y: s.y, mode: s.mode })),
      crew: this.sim.crew,
    };
    const str = JSON.stringify(state);
    for (const ws of this.commands) if (ws.readyState === 1) ws.send(str);
  }

  snapshotLog(ws) { send(ws, { type: 'logs', entries: this.log.slice(-120) }); }

  // ---------- automation: silence window ----------
  startSilence(sec) {
    this.silenceUntil = now() + sec * 1000;
    for (const n of this.nodes.values()) send(n.ws, { type: 'silence', until: this.silenceUntil });
    this.addLog('warn', `Silence window: ${sec} s. All phones switch to high-sensitivity listening; crew please hold still.`);
  }

  // ---------- automation: acoustic self-mapping (BeepBeep ranging) ----------
  startRanging() {
    if (this.ranging && this.ranging.phase !== 'done') return this.addLog('warn', 'Auto-Map is already running.');
    const real = this.aliveNodes().filter((n) => !n.virtual);
    const virt = this.aliveNodes().filter((n) => n.virtual);
    if (real.length >= 2) {
      const slotMs = 750;
      const startAt = now() + 2500;
      const ids = real.map((n) => n.id);
      const durMs = ids.length * slotMs + 900;
      this.ranging = { id: Math.random().toString(36).slice(2, 8), ids, startAt, slotMs, durMs, endAt: startAt + durMs, results: {}, phase: 'chirping' };
      ids.forEach((id, i) => send(this.nodes.get(id).ws, { type: 'ranging', session: this.ranging.id, ids, index: i, startAt, slotMs, durMs }));
      this.addLog('info', `Auto-Map: ${ids.length} phones will chirp in turn and measure the distances between them. Keep them still.`);
      this.ranging.timeout = setTimeout(() => this.solveRanging(), durMs + 2500 + 9000);
    } else if (virt.length >= 3) {
      this.simRanging(virt);
    } else {
      this.addLog('warn', 'Auto-Map needs at least 2 live phones (or 3 simulated nodes).');
    }
  }

  onRangingResult(node, m) {
    const r = this.ranging;
    if (!r || m.session !== r.id) return;
    r.results[node.id] = m.arrivals;
    if (m.levels) r.levels = { ...(r.levels || {}), [node.id]: m.levels };
    if (Object.keys(r.results).length === r.ids.length) { clearTimeout(r.timeout); this.solveRanging(); }
  }

  solveRanging() {
    const r = this.ranging;
    if (!r || r.phase === 'done') return;
    r.phase = 'done';
    const ids = r.ids.filter((id) => r.results[id]);
    if (ids.length < 2) return this.addLog('warn', 'Auto-Map failed: not enough phones reported chirp arrivals.');
    const D = rangingDistances(ids, r.results);
    const valid = D.flat().filter((d, i) => d != null && d > 0).length;
    if (!valid) return this.addLog('warn', "Auto-Map failed: the phones couldn't hear each other's chirps. Turn the volume up and move them closer.");
    const { points, stress } = mds2d(D);
    this.applyLayout(ids, points);
    const pairs = [];
    for (let i = 0; i < ids.length; i++) for (let j = i + 1; j < ids.length; j++) pairs.push({ a: ids[i], b: ids[j], d: D[i][j] });
    for (const ws of this.commands) send(ws, { type: 'mapped', pairs, stress });
    this.addLog('good', `Auto-Map done. ${ids.length} phones positioned from their chirps (fit error ${(stress * 100).toFixed(0)}%).`);
  }

  applyLayout(ids, pts, keepFrame = false) {
    let P = pts;
    if (!keepFrame) {
      const xs = P.map((p) => p.x), ys = P.map((p) => p.y);
      const cx = (Math.min(...xs) + Math.max(...xs)) / 2, cy = (Math.min(...ys) + Math.max(...ys)) / 2;
      P = P.map((p) => ({ x: p.x - cx + this.bounds.w / 2, y: p.y - cy + this.bounds.h / 2 }));
    }
    ids.forEach((id, i) => {
      const n = this.nodes.get(id);
      n.x = clamp(P[i].x, 0.2, this.bounds.w - 0.2);
      n.y = clamp(P[i].y, 0.2, this.bounds.h - 0.2);
      n.placed = true;
      send(n.ws, { type: 'placed', x: n.x, y: n.y });
    });
  }

  // ---------- automation: knock-back consciousness probe ----------
  startProbe(candId, lang) {
    const c = this.candidates.find((c) => c.id === candId);
    if (!c) return this.addLog('warn', 'That candidate no longer exists.');
    const pool = this.aliveNodes().filter((n) => n.placed);
    if (!pool.length) return this.addLog('warn', 'No placed nodes available to run the probe.');
    const node = pool.sort((a, b) => Math.hypot(a.x - c.x, a.y - c.y) - Math.hypot(b.x - c.x, b.y - c.y))[0];
    const probeId = Math.random().toString(36).slice(2, 8);
    this.probes.set(probeId, { candId, nodeId: node.id, t: now() });
    this.addLog('info', `Knock-back probe: ${node.name} is calling toward candidate #${c.id} (${lang.toUpperCase()}). Listening for a reply…`);
    if (node.virtual) {
      const s = this.sim.survivors.find((s) => Math.hypot(s.x - c.x, s.y - c.y) < 5);
      setTimeout(() => {
        if (s && s.mode !== 'silent') {
          [0, 0.55, 1.1].forEach((d) => setTimeout(() => this.emitSound(s.x, s.y, 'impact', -13, true), d * 1000));
          setTimeout(() => this.onProbeResult(node, { probeId, taps: 3 }), 1800);
        } else this.onProbeResult(node, { probeId, taps: 0 });
      }, 4500);
    } else {
      send(node.ws, { type: 'probe', probeId, lang, knocks: 3, listenMs: 9000 });
    }
  }

  onProbeResult(node, m) {
    const p = this.probes.get(m.probeId);
    if (!p) return;
    this.probes.delete(m.probeId);
    const c = this.candidates.find((c) => c.id === p.candId);
    const ok = m.taps >= 2;
    if (c) c.responsive = ok ? true : c.responsive === true ? true : false;
    if (ok) this.addLog('alert', `Candidate #${p.candId} answered with ${m.taps} knock(s): the survivor is conscious and responding.`, c ? { x: c.x, y: c.y } : undefined);
    else this.addLog('warn', `No knock reply from candidate #${p.candId} (${m.taps} taps heard). They may be unconscious or out of range; send the team with priority.`);
  }

  // ---------- simulation (demo without phones) ----------
  onSim(m) {
    if (m.action === 'nodes') {
      const k = clamp(m.count || 6, 3, 12);
      const W = this.bounds.w, H = this.bounds.h;
      const base = [...this.nodes.values()].filter((n) => n.virtual).length;
      for (let i = 0; i < k; i++) {
        const a = (i / k) * Math.PI * 2 + 0.4;
        const tx = W / 2 + Math.cos(a) * W * 0.34 + gauss() * 1.2;
        const ty = H / 2 + Math.sin(a) * H * 0.32 + gauss() * 1.0;
        const idx = this.nodes.size;
        const id = `v${base + i + 1}-${Math.random().toString(36).slice(2, 5)}`;
        this.nodes.set(id, {
          id, name: `SIM-${base + i + 1}`, color: COLORS[idx % COLORS.length], virtual: true, placed: false,
          ...this.parkingSpot(idx), truePos: { x: clamp(tx, 0.5, W - 0.5), y: clamp(ty, 0.5, H - 0.5) },
          floor: -64 + Math.random() * 6, level: -80, gain: 0, syncSigma: 0.012, rtt: 18, events: 0, motion: true,
          device: 'Simulated phone', lastSeen: now(),
        });
      }
      this.addLog('good', `${k} simulated phones were scattered across the rubble. Run Auto-Map to locate them from their chirps.`);
    } else if (m.action === 'survivor') {
      const s = { id: Math.random().toString(36).slice(2, 6), x: clamp(m.x, 0, this.bounds.w), y: clamp(m.y, 0, this.bounds.h), mode: m.mode || 'sos', next: now() + 1200 };
      this.sim.survivors.push(s);
      this.addLog('info', `Hidden survivor placed (${s.mode === 'sos' ? 'knocking in bursts of 3' : s.mode === 'weak' ? 'weak calls and breathing' : 'unconscious, silent'}). Only the judge knows where.`);
    } else if (m.action === 'crew') {
      this.sim.crew = !this.sim.crew;
      this.addLog('info', `Rescue-crew noise ${this.sim.crew ? 'ON (voices and machinery on the surface)' : 'OFF'}.`);
    } else if (m.action === 'clear') {
      for (const [id, n] of this.nodes) if (n.virtual) this.nodes.delete(id);
      this.sim.survivors = [];
      this.sim.crew = false;
      this.heat.fill(0); this.history = []; this.candidates = [];
      this.addLog('info', 'Simulation cleared.');
    }
  }

  simStep() {
    const t = now();
    const quiet = t < this.silenceUntil;
    for (const s of this.sim.survivors) {
      if (t < s.next || s.mode === 'silent') continue;
      if (s.mode === 'sos') {
        const n = 3, gap = 0.42 + Math.random() * 0.08;
        for (let i = 0; i < n; i++) setTimeout(() => this.emitSound(s.x, s.y, 'impact', -15 + gauss() * 2, true), i * gap * 1000);
        s.next = t + (quiet ? 3500 : 5500) + Math.random() * 2500;
      } else if (s.mode === 'weak') {
        this.emitSound(s.x, s.y, Math.random() < 0.6 ? 'voice' : 'periodic', quiet ? -30 : -34, false);
        s.next = t + 3000 + Math.random() * 3000;
      }
    }
    if (this.sim.crew && !quiet && t > this.sim.nextCrew) {
      const edge = Math.random() < 0.5;
      const x = edge ? (Math.random() < 0.5 ? 0.5 : this.bounds.w - 0.5) : Math.random() * this.bounds.w;
      const y = edge ? Math.random() * this.bounds.h : (Math.random() < 0.5 ? 0.5 : this.bounds.h - 0.5);
      this.emitSound(x, y, Math.random() < 0.6 ? 'voice' : 'other', -10 + gauss() * 3, false);
      this.sim.nextCrew = t + 1500 + Math.random() * 2500;
    }
  }

  emitSound(x, y, cls, S, seismic) {
    const t = now() / 1000;
    for (const n of this.nodes.values()) {
      if (!n.virtual) continue;
      const p = n.truePos || n;
      const r = Math.max(0.4, Math.hypot(p.x - x, p.y - y));
      const level = S - pathLoss(r) + gauss() * 3;
      n.level = Math.max(n.level * 0.5 + level * 0.5, n.floor);
      if (level < n.floor + DETECT_MARGIN) continue;
      const mis = Math.random() < 0.08;
      this.ingest(n, { t: t + r / C + gauss() * 0.006, level, cls: mis ? 'other' : cls, conf: 0.65 + Math.random() * 0.3, seismic: seismic && r < 7, floor: n.floor });
    }
  }

  simRanging(virt) {
    this.ranging = { phase: 'chirping', startAt: now(), endAt: now() + virt.length * 750 + 900 };
    this.addLog('info', `Auto-Map: ${virt.length} simulated phones chirping in turn…`);
    setTimeout(() => {
      const ids = virt.map((n) => n.id);
      const arrivals = {};
      const lat = Object.fromEntries(ids.map((id) => [id, Math.random() * 0.15])); // unknown per-device start latency
      ids.forEach((i, a) => {
        arrivals[i] = {};
        ids.forEach((j, b) => {
          const pi = this.nodes.get(i).truePos, pj = this.nodes.get(j).truePos;
          const r = i === j ? 0.12 : Math.hypot(pi.x - pj.x, pi.y - pj.y);
          arrivals[i][j] = b * 0.75 + lat[j] + r / C + gauss() * 0.00015 + 3.1 * a; // each node's own clock origin differs
        });
      });
      const D = rangingDistances(ids, arrivals);
      const { points, stress } = mds2d(D);
      // Procrustes-align to ground truth purely so the simulated survivor stays in the same frame
      const truth = ids.map((id) => this.nodes.get(id).truePos);
      const aligned = procrustes(points, truth);
      const err = Math.sqrt(aligned.reduce((a, p, i) => a + (p.x - truth[i].x) ** 2 + (p.y - truth[i].y) ** 2, 0) / ids.length);
      this.applyLayout(ids, aligned, true);
      const pairs = [];
      for (let i = 0; i < ids.length; i++) for (let j = i + 1; j < ids.length; j++) pairs.push({ a: ids[i], b: ids[j], d: D[i][j] });
      for (const ws of this.commands) send(ws, { type: 'mapped', pairs, stress });
      this.ranging.phase = 'done';
      this.addLog('good', `Auto-Map done. ${ids.length} phones positioned from their chirps with no GPS (RMS error ${(err * 100).toFixed(0)} cm).`);
    }, virt.length * 750 + 900);
  }
}

function procrustes(P, Q) {
  const n = P.length;
  const mp = P.reduce((a, p) => ({ x: a.x + p.x / n, y: a.y + p.y / n }), { x: 0, y: 0 });
  const mq = Q.reduce((a, p) => ({ x: a.x + p.x / n, y: a.y + p.y / n }), { x: 0, y: 0 });
  const best = [1, -1].map((flip) => {
    const A = P.map((p) => ({ x: p.x - mp.x, y: (p.y - mp.y) * flip }));
    const B = Q.map((p) => ({ x: p.x - mq.x, y: p.y - mq.y }));
    let sxx = 0, sxy = 0;
    A.forEach((a, i) => { sxx += a.x * B[i].x + a.y * B[i].y; sxy += a.x * B[i].y - a.y * B[i].x; });
    const th = Math.atan2(sxy, sxx), c = Math.cos(th), s = Math.sin(th);
    const R = A.map((a) => ({ x: a.x * c - a.y * s + mq.x, y: a.x * s + a.y * c + mq.y }));
    const e = R.reduce((acc, r, i) => acc + (r.x - Q[i].x) ** 2 + (r.y - Q[i].y) ** 2, 0);
    return { R, e };
  });
  return best[0].e < best[1].e ? best[0].R : best[1].R;
}

function clamp(v, a, b) { return Math.max(a, Math.min(b, v)); }

module.exports = { Site };
