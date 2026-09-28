// EchoSwarm phone node: turns this phone into an acoustic + seismic survivor sensor.
import { Link, qs, store, localNow } from './net.js';

const $ = (s) => document.querySelector(s);
const NATIVE = !!(window.Capacitor && window.Capacitor.isNativePlatform && window.Capacitor.isNativePlatform());
const Plugins = (window.Capacitor && window.Capacitor.Plugins) || {};
const ui = {
  join: $('#join'), live: $('#live'), code: $('#code'), name: $('#name'), go: $('#go'), err: $('#err'), server: $('#server'),
  site: $('#siteCode'), nodeName: $('#nodeName'), db: $('#db'), floor: $('#floor'), meter: $('#meterFill'),
  chips: { net: $('#cNet'), sync: $('#cSync'), mic: $('#cMic'), motion: $('#cMotion'), wake: $('#cWake'), pos: $('#cPos') },
  count: $('#evCount'), last: $('#lastEv'), overlay: $('#overlay'), ovTitle: $('#ovTitle'), ovMode: $('#ovMode'), ovText: $('#ovText'), ovCount: $('#ovCount'),
  canvas: $('#radar'), feed: $('#feed'),
};

// ---------------- state ----------------
const S = {
  site: (qs('site') || store('es.site') || '').toUpperCase(),
  server: NATIVE ? store('es.server') || window.ES_DEFAULT_SERVER || '' : '',
  clientId: store('es.cid') || `p${Math.random().toString(36).slice(2, 10)}`,
  name: store('es.name') || '',
  ctx: null, sr: 48000, worklet: null,
  floor: null, floorInit: [], dbNow: -90, dbMax1s: -90,
  acOff: null, acOffWin: [],
  ev: null, refractoryUntil: 0, muteUntil: 0, count: 0,
  motion: { ok: false, lp: 9.81, floor: 0.02, spikes: [] },
  silenceUntil: 0, envSil: [], envAcc: { s: 0, n: 0, t: 0 },
  ranging: null, probe: null, wake: null, color: '#38bdf8',
  ripples: [],
};
store('es.cid', S.clientId);
ui.code.value = S.site;
ui.name.value = S.name;
if (NATIVE) { $('#serverField').hidden = false; ui.server.value = S.server; }
let link = null;

// ---------------- join ----------------
ui.go.addEventListener('click', async () => {
  S.site = ui.code.value.trim().toUpperCase();
  S.name = ui.name.value.trim();
  if (NATIVE) {
    S.server = ui.server.value.trim().replace(/\/+$/, '');
    if (S.server && !/^https?:\/\//.test(S.server)) S.server = `https://${S.server}`;
    if (!S.server) return (ui.err.textContent = 'Enter the server address, or scan the QR code on the command screen.');
    store('es.server', S.server);
  }
  if (!S.site) return (ui.err.textContent = 'Enter the 4-letter site code shown on the command screen.');
  store('es.site', S.site);
  store('es.name', S.name);
  ui.go.disabled = true;
  ui.err.textContent = '';
  try {
    await startSensors(); // must run inside the tap gesture (iOS)
  } catch (e) {
    ui.go.disabled = false;
    ui.err.textContent = micHelp(e);
    return;
  }
  ui.join.hidden = true;
  ui.live.hidden = false;
  ui.site.textContent = S.site;
  connect();
  requestAnimationFrame(draw);
});

function micHelp(e) {
  if (NATIVE && e && e.name === 'NotAllowedError') return 'Microphone access is off. Enable it for EchoSwarm in your phone settings.';
  if (!window.isSecureContext) return 'The microphone needs HTTPS. Open this page through the https:// link or the QR code.';
  if (e && e.name === 'NotAllowedError') return 'Microphone permission was denied. Allow it in your browser settings and try again.';
  return `Could not start the sensors: ${e && e.message ? e.message : e}`;
}

function connect() {
  const device = navigator.userAgentData?.platform || (/iPhone|iPad/.test(navigator.userAgent) ? 'iPhone' : /Android/.test(navigator.userAgent) ? 'Android' : 'Browser');
  link = new Link(
    { type: 'hello', role: 'node', site: S.site, clientId: S.clientId, name: S.name, device },
    onServer,
    (up) => chip('net', up ? 'ok' : 'bad', up ? 'Online' : 'Reconnecting'),
    S.server,
  );
  setInterval(sendStatus, 1000);
}

// ---------------- sensors ----------------
async function startSensors() {
  // Motion permission (iOS 13+) must be requested from a user gesture, before any await
  let motionReq = null;
  if (typeof DeviceMotionEvent !== 'undefined' && typeof DeviceMotionEvent.requestPermission === 'function') {
    motionReq = DeviceMotionEvent.requestPermission().catch(() => 'denied');
  }
  const AC = window.AudioContext || window.webkitAudioContext;
  S.ctx = new AC({ latencyHint: 'interactive' });
  try { if (navigator.audioSession) navigator.audioSession.type = 'play-and-record'; } catch {}
  const stream = await navigator.mediaDevices.getUserMedia({
    audio: { echoCancellation: false, noiseSuppression: false, autoGainControl: false, channelCount: 1 },
  });
  await S.ctx.resume();
  S.sr = S.ctx.sampleRate;
  await S.ctx.audioWorklet.addModule('/js/sensor-worklet.js');
  const src = S.ctx.createMediaStreamSource(stream);
  S.worklet = new AudioWorkletNode(S.ctx, 'echoswarm-sensor');
  const sink = S.ctx.createGain();
  sink.gain.value = 0;
  src.connect(S.worklet).connect(sink).connect(S.ctx.destination);
  S.worklet.port.onmessage = (e) => (e.data.type === 'feat' ? onFeatures(e.data) : onRecording(e.data));
  chip('mic', 'ok', `Mic ${Math.round(S.sr / 1000)} kHz`);

  const perm = motionReq ? await motionReq : 'granted';
  if (perm === 'granted' && 'DeviceMotionEvent' in window) {
    window.addEventListener('devicemotion', onMotion);
    S.motion.ok = true;
    chip('motion', 'ok', 'Vibration');
  } else chip('motion', 'warn', 'No vibration');

  await keepAwake();
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') { keepAwake(); S.ctx.resume(); }
  });
}

async function keepAwake() {
  if (Plugins.KeepAwake) {
    try { await Plugins.KeepAwake.keepAwake(); chip('wake', 'ok', 'Screen on'); return; } catch {}
  }
  try {
    if ('wakeLock' in navigator) {
      S.wake = await navigator.wakeLock.request('screen');
      chip('wake', 'ok', 'Screen on');
      S.wake.addEventListener('release', () => chip('wake', 'warn', 'Screen may sleep'));
      return;
    }
  } catch {}
  chip('wake', 'warn', 'Keep screen on');
}

function onMotion(e) {
  const a = e.acceleration && e.acceleration.x != null ? e.acceleration : e.accelerationIncludingGravity;
  if (!a || a.x == null) return;
  const mag = Math.hypot(a.x, a.y, a.z);
  const M = S.motion;
  M.lp = M.lp * 0.9 + mag * 0.1;
  const hp = Math.abs(mag - M.lp);
  const t = performance.now();
  if (hp > Math.max(0.06, M.floor * 5)) M.spikes.push({ t, v: hp });
  else M.floor = M.floor * 0.995 + hp * 0.005;
  while (M.spikes.length && t - M.spikes[0].t > 3000) M.spikes.shift();
}

// map an audio-clock frame to performance.now() milliseconds
function frameToPerf(f) { return (f / S.sr) * 1000 + S.acOff; }
function perfToFrame(p) { return Math.round(((p - S.acOff) / 1000) * S.sr); }

function onFeatures(d) {
  const nb = d.rms.length, bs = d.bs;
  // audio-clock ↔ performance-clock mapping (min over recent windows = least-delayed delivery)
  const est = performance.now() - ((d.f + nb * bs) / S.sr) * 1000;
  S.acOffWin.push(est);
  if (S.acOffWin.length > 400) S.acOffWin.shift();
  S.acOff = Math.min(...S.acOffWin.slice(-400));

  for (let i = 0; i < nb; i++) {
    const f = d.f + i * bs;
    const db = 20 * Math.log10(d.rms[i] + 1e-9);
    S.dbNow = db;
    if (db > S.dbMax1s) S.dbMax1s = db;
    block(f, db, d.zcr[i], d.low[i], d.high[i], d.rms[i] * d.rms[i], bs);
  }
}

function block(f, db, zcr, low, high, energy, bs) {
  // --- adaptive noise floor ---
  if (S.floor === null) {
    S.floorInit.push(db);
    if (S.floorInit.length > 120) { const s = [...S.floorInit].sort((a, b) => a - b); S.floor = s[Math.floor(s.length * 0.3)]; }
    return;
  }
  const silence = link && link.serverNow() < S.silenceUntil;
  const margin = silence ? 6 : 9;
  const tPerf = frameToPerf(f);

  // silence-window envelope at 10 Hz (for breathing / rhythmic faint sound)
  if (silence) {
    const A = S.envAcc;
    A.s += db; A.n++;
    if (tPerf - A.t >= 100) { if (A.n) S.envSil.push(A.s / A.n); A.s = 0; A.n = 0; A.t = tPerf; }
  }

  const blocked = S.ranging || tPerf < S.muteUntil;
  const ev = S.ev;
  if (!ev) {
    if (!blocked && db > S.floor + margin && tPerf > S.refractoryUntil) {
      S.ev = { f, t: tPerf, peak: db, peakIdx: 0, n: 1, below: 0, zcr, low, high, energy, margin };
    } else if (!ev) {
      // track floor: fast down, slow up
      S.floor = db < S.floor ? S.floor * 0.95 + db * 0.05 : S.floor + 0.004;
    }
    return;
  }
  ev.n++;
  ev.zcr += zcr; ev.low += low; ev.high += high; ev.energy += energy;
  if (db > ev.peak) { ev.peak = db; ev.peakIdx = ev.n - 1; }
  if (db < S.floor + ev.margin - 3) ev.below++; else ev.below = 0;
  const durMs = (ev.n * bs / S.sr) * 1000;
  if (ev.below >= 8 || durMs > 2500) {
    S.ev = null;
    S.refractoryUntil = tPerf + 60;
    const activeMs = durMs - (ev.below * bs / S.sr) * 1000;
    if (activeMs >= 5 && !blocked) finishEvent(ev, activeMs, bs);
  }
}

function classify(ev, durMs, bs) {
  const n = ev.n;
  const zcr = ev.zcr / n;
  const tot = ev.energy || 1e-12;
  const lowF = ev.low / tot, highF = ev.high / tot;
  const attackMs = (ev.peakIdx * bs / S.sr) * 1000;
  const snr = ev.peak - S.floor;
  if (durMs < 260 && attackMs < 25) return { cls: 'impact', conf: Math.min(0.97, 0.6 + snr / 60 + (lowF > 0.3 ? 0.08 : 0)) };
  if (durMs >= 120 && zcr > 0.008 && zcr < 0.16 && highF < 0.4) return { cls: 'voice', conf: Math.min(0.9, 0.5 + durMs / 3000 + snr / 80) };
  return { cls: 'other', conf: 0.5 };
}

function finishEvent(ev, durMs, bs) {
  const { cls, conf } = classify(ev, durMs, bs);
  const M = S.motion;
  const seismic = M.ok && M.spikes.some((s) => s.t > ev.t - 90 && s.t < ev.t + 160);
  const serverT = ev.t + performance.timeOrigin + link.offset;
  link.send({ type: 'event', t: serverT, level: +ev.peak.toFixed(1), floor: +S.floor.toFixed(1), cls, conf: +conf.toFixed(2), dur: Math.round(durMs), seismic });
  S.count++;
  ui.count.textContent = S.count;
  const label = { impact: 'Knock / impact', voice: 'Voice-like', other: 'Other sound' }[cls];
  ui.last.textContent = `${label}${seismic ? ' + vibration' : ''} · ${Math.round(ev.peak - S.floor)} dB above noise`;
  S.ripples.push({ t: performance.now(), cls, seismic, s: Math.min(1, (ev.peak - S.floor) / 30) });
  if (S.probe && cls === 'impact' && performance.now() > S.probe.listenFrom) S.probe.taps++;
  feed(`${label}${seismic ? ' + structure vibration' : ''}`, cls);
}

function feed(text, cls) {
  const li = document.createElement('li');
  li.className = cls;
  li.innerHTML = `<time>${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}</time><i></i><span></span>`;
  li.lastChild.textContent = text;
  ui.feed.prepend(li);
  while (ui.feed.children.length > 5) ui.feed.lastChild.remove();
}

function sendStatus() {
  if (!link || S.floor === null) return;
  link.send({ type: 'status', floor: +S.floor.toFixed(1), level: +S.dbMax1s.toFixed(1), motion: S.motion.ok, rtt: link.rtt != null ? Math.round(link.rtt) : null });
  ui.db.textContent = `${Math.round(S.dbMax1s)}`;
  ui.floor.textContent = `${Math.round(S.floor)}`;
  S.dbMax1s = -120;
  if (link.rtt != null) chip('sync', link.rtt < 60 ? 'ok' : 'warn', `Sync ±${Math.max(1, Math.round(link.rtt / 2))} ms`);
  // end of a silence window → rhythmic faint-sound analysis
  if (S.silenceUntil && link.serverNow() > S.silenceUntil) {
    analysePeriodic(S.silenceUntil);
    S.silenceUntil = 0;
    hideOverlay();
  }
}

function analysePeriodic(untilServer) {
  const env = S.envSil;
  S.envSil = [];
  if (env.length < 80) return;
  const m = env.reduce((a, b) => a + b, 0) / env.length;
  const x = env.map((v) => v - m);
  const r0 = x.reduce((a, v) => a + v * v, 0);
  if (r0 < 1e-6) return;
  let best = 0, lag = 0;
  for (let L = 20; L <= 60 && L < x.length / 2; L++) {
    let r = 0;
    for (let i = 0; i + L < x.length; i++) r += x[i] * x[i + L];
    r /= r0;
    if (r > best) { best = r; lag = L; }
  }
  const sorted = [...env].sort((a, b) => a - b);
  const swing = sorted[Math.floor(sorted.length * 0.9)] - sorted[Math.floor(sorted.length * 0.1)];
  if (best > 0.4 && swing > 1.5) {
    link.send({ type: 'event', t: untilServer, level: +sorted[Math.floor(sorted.length * 0.9)].toFixed(1), floor: +S.floor.toFixed(1), cls: 'periodic', conf: +Math.min(0.9, best).toFixed(2), dur: 0, seismic: false });
    feed(`Rhythmic faint sound every ${(lag / 10).toFixed(1)} s (possible breathing)`, 'periodic');
  }
}

// ---------------- server commands ----------------
function onServer(m) {
  switch (m.type) {
    case 'welcome':
      S.color = m.color;
      ui.nodeName.textContent = m.name;
      document.documentElement.style.setProperty('--node', m.color);
      if (m.silenceUntil > Date.now()) startSilenceUI(m.silenceUntil);
      chip('pos', m.placed ? 'ok' : 'warn', m.placed ? 'On map' : 'Not placed');
      break;
    case 'placed':
      chip('pos', 'ok', `(${m.x.toFixed(1)}, ${m.y.toFixed(1)}) m`);
      break;
    case 'silence': startSilenceUI(m.until); break;
    case 'identify': identify(); break;
    case 'ranging': startRanging(m); break;
    case 'probe': startProbe(m); break;
    case 'removed': ui.last.textContent = 'This node was removed by command.'; break;
  }
}

function chip(k, state, text) {
  const c = ui.chips[k];
  if (!c) return;
  c.className = `status ${state}`;
  c.textContent = text;
}

const MODE_LABEL = { silence: 'Silence window', ranging: 'Auto-map', probe: 'Knock-back probe' };
function showOverlay(kind, title, text) {
  ui.overlay.className = `overlay ${kind}`;
  ui.ovMode.textContent = MODE_LABEL[kind] || '';
  ui.overlay.hidden = false;
  ui.ovTitle.textContent = title;
  ui.ovText.textContent = text;
  ui.ovCount.textContent = '';
}
function hideOverlay() { ui.overlay.hidden = true; }

function startSilenceUI(until) {
  S.silenceUntil = until;
  S.envSil = [];
  navigator.vibrate?.([300, 120, 300]);
  showOverlay('silence', 'Hold still. Stay quiet.', 'Every phone on site is listening at high sensitivity for faint knocks and breathing.');
  const tick = () => {
    if (!S.silenceUntil) return;
    const left = Math.max(0, Math.ceil((S.silenceUntil - link.serverNow()) / 1000));
    ui.ovCount.textContent = `${left}s`;
    if (left > 0) setTimeout(tick, 250);
  };
  tick();
}

function identify() {
  navigator.vibrate?.([200, 100, 200, 100, 200]);
  beep(1320, 0.12, 0.4);
  setTimeout(() => beep(1760, 0.12, 0.4), 180);
  document.body.classList.add('flash');
  setTimeout(() => document.body.classList.remove('flash'), 1600);
}

function beep(freq, dur, gain = 0.3, when = 0) {
  const ctx = S.ctx, t = ctx.currentTime + when;
  const o = ctx.createOscillator(), g = ctx.createGain();
  o.frequency.value = freq;
  g.gain.setValueAtTime(0, t);
  g.gain.linearRampToValueAtTime(gain, t + 0.01);
  g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
  o.connect(g).connect(ctx.destination);
  o.start(t); o.stop(t + dur + 0.02);
}

// ---------------- acoustic self-mapping (BeepBeep ranging) ----------------
function makeChirp() {
  const n = Math.round(S.sr * 0.05), f0 = 2000, f1 = 6500, T = n / S.sr;
  const c = new Float32Array(n);
  for (let i = 0; i < n; i++) {
    const t = i / S.sr;
    const w = 0.5 - 0.5 * Math.cos((2 * Math.PI * i) / (n - 1));
    c[i] = w * Math.sin(2 * Math.PI * (f0 * t + ((f1 - f0) / (2 * T)) * t * t));
  }
  return c;
}

function startRanging(m) {
  const chirp = makeChirp();
  S.ranging = { ...m, chirp };
  showOverlay('ranging', 'Measuring distances', 'The phones are chirping in turn to work out where each one is. Keep this phone still.');
  const recFromServer = m.startAt - 300;
  const frames = Math.round(((m.durMs + 600) / 1000) * S.sr);
  const armIn = Math.max(0, link.toLocal(recFromServer) - localNow());
  setTimeout(() => S.worklet.port.postMessage({ cmd: 'record', frames }), armIn);
  // play own chirp at our slot, scheduled on the audio clock
  const slotServer = m.startAt + m.index * m.slotMs;
  const when = S.ctx.currentTime + (slotServer - link.serverNow()) / 1000;
  const buf = S.ctx.createBuffer(1, chirp.length, S.sr);
  buf.copyToChannel(chirp, 0);
  const src = S.ctx.createBufferSource();
  const g = S.ctx.createGain();
  g.gain.value = 1;
  src.buffer = buf;
  src.connect(g).connect(S.ctx.destination);
  src.start(Math.max(S.ctx.currentTime + 0.05, when));
  navigator.vibrate?.(80);
}

function onRecording(d) {
  const R = S.ranging;
  if (!R) return;
  ui.ovText.textContent = 'Measuring chirp arrival times…';
  setTimeout(() => {
    const arrivals = {};
    const x = d.data, c = R.chirp, L = c.length;
    R.ids.forEach((id, j) => {
      const slotServer = R.startAt + j * R.slotMs;
      const expPerf = link.toLocal(slotServer) - performance.timeOrigin;
      const expFrame = perfToFrame(expPerf) - d.start;
      const a = Math.max(0, expFrame - Math.round(0.2 * S.sr));
      const b = Math.min(x.length - L, expFrame + Math.round(0.55 * S.sr));
      let best = 0, bi = -1, sum = 0, cnt = 0;
      for (let k = a; k < b; k += 1) {
        let s = 0;
        for (let i = 0; i < L; i += 2) s += x[k + i] * c[i];
        const v = Math.abs(s);
        sum += v; cnt++;
        if (v > best) { best = v; bi = k; }
      }
      const mean = cnt ? sum / cnt : 0;
      arrivals[id] = bi >= 0 && best > mean * 6 ? (d.start + bi) / S.sr : null;
    });
    link.send({ type: 'rangingResult', session: R.session, arrivals });
    S.ranging = null;
    const heard = Object.values(arrivals).filter((v) => v != null).length;
    ui.ovText.textContent = `Heard ${heard}/${R.ids.length} chirps. Sent to command.`;
    setTimeout(hideOverlay, 1800);
  }, 30);
}

// ---------------- knock-back consciousness probe ----------------
const PROMPTS = {
  en: { lang: 'en-IN', text: 'Rescue team here. If you can hear me, knock three times.' },
  ta: { lang: 'ta-IN', text: 'மீட்புக் குழு வந்துள்ளது. நான் பேசுவது கேட்டால், மூன்று முறை தட்டுங்கள்.' },
  hi: { lang: 'hi-IN', text: 'बचाव दल यहाँ है। अगर आप मुझे सुन सकते हैं, तो तीन बार खटखटाइए।' },
};

function startProbe(m) {
  const p = PROMPTS[m.lang] || PROMPTS.en;
  showOverlay('probe', 'Calling the survivor', p.text);
  S.probe = { id: m.probeId, taps: 0, listenFrom: Infinity };
  const speakMs = 5500;
  S.muteUntil = performance.now() + speakMs + 2600;
  try {
    const u = new SpeechSynthesisUtterance(p.text);
    u.lang = p.lang; u.rate = 0.9; u.volume = 1;
    speechSynthesis.cancel();
    speechSynthesis.speak(u);
  } catch {}
  // three demonstration knocks after the prompt
  setTimeout(() => { for (let i = 0; i < 3; i++) knock(i * 0.5); }, speakMs);
  setTimeout(() => {
    S.probe.listenFrom = performance.now();
    ui.ovTitle.textContent = 'Listening for a reply';
    const end = performance.now() + m.listenMs;
    const tick = () => {
      const left = Math.ceil((end - performance.now()) / 1000);
      ui.ovCount.textContent = `${S.probe.taps} knock${S.probe.taps === 1 ? '' : 's'} · ${Math.max(0, left)}s`;
      if (left > 0) return setTimeout(tick, 200);
      link.send({ type: 'probeResult', probeId: S.probe.id, taps: S.probe.taps });
      ui.ovText.textContent = S.probe.taps >= 2 ? 'Reply received. Survivor is responsive.' : 'No clear reply.';
      S.probe = null;
      setTimeout(hideOverlay, 2500);
    };
    tick();
  }, speakMs + 2200);
}

function knock(when) {
  const ctx = S.ctx, t = ctx.currentTime + when;
  const n = Math.round(ctx.sampleRate * 0.09);
  const buf = ctx.createBuffer(1, n, ctx.sampleRate);
  const ch = buf.getChannelData(0);
  for (let i = 0; i < n; i++) {
    const e = Math.exp(-i / (ctx.sampleRate * 0.012));
    ch[i] = e * (0.7 * Math.sin((2 * Math.PI * 160 * i) / ctx.sampleRate) + 0.5 * (Math.random() * 2 - 1));
  }
  const s = ctx.createBufferSource();
  s.buffer = buf;
  s.connect(ctx.destination);
  s.start(t);
}

// ---------------- scope visual ----------------
const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
const CLS_COLOR = { impact: '#ff6a1a', voice: '#b8a4ff', other: '#75726c' };
function draw() {
  const cv = ui.canvas, dpr = Math.min(2, window.devicePixelRatio || 1);
  const w = cv.clientWidth, h = cv.clientHeight;
  if (cv.width !== Math.round(w * dpr)) { cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr); }
  const g = cv.getContext('2d');
  g.setTransform(dpr, 0, 0, dpr, 0, 0);
  g.clearRect(0, 0, w, h);
  const cx = w / 2, cy = h / 2, R = Math.min(w, h) / 2 - 10;
  const t = performance.now();

  // instrument face: rings, crosshair, 72 ticks
  g.strokeStyle = '#262a2e'; g.lineWidth = 1;
  for (let i = 1; i <= 4; i++) { g.beginPath(); g.arc(cx, cy, (R * i) / 4, 0, Math.PI * 2); g.stroke(); }
  g.beginPath(); g.moveTo(cx - R, cy); g.lineTo(cx + R, cy); g.moveTo(cx, cy - R); g.lineTo(cx, cy + R); g.stroke();
  g.strokeStyle = '#3a3f45';
  for (let i = 0; i < 72; i++) {
    const a = (i / 72) * Math.PI * 2, L = i % 6 === 0 ? 9 : 4;
    g.beginPath(); g.moveTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R); g.lineTo(cx + Math.cos(a) * (R - L), cy + Math.sin(a) * (R - L)); g.stroke();
  }
  // sweep line
  if (!reduceMotion) {
    const a = (t / 2400) % (Math.PI * 2);
    g.strokeStyle = 'rgba(235,232,226,0.35)';
    g.beginPath(); g.moveTo(cx, cy); g.lineTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R); g.stroke();
  }
  // live level: filled disc scaled by dB above floor, threshold ring
  if (S.floor !== null) {
    const lvl = Math.max(0, Math.min(1, (S.dbNow - S.floor) / 30));
    const thr = Math.min(1, (link && link.serverNow() < S.silenceUntil ? 6 : 9) / 30);
    g.fillStyle = 'rgba(235,232,226,0.08)';
    g.beginPath(); g.arc(cx, cy, 10 + lvl * (R - 10), 0, Math.PI * 2); g.fill();
    g.strokeStyle = '#ebe8e2'; g.lineWidth = 1.5;
    g.beginPath(); g.arc(cx, cy, 10 + lvl * (R - 10), 0, Math.PI * 2); g.stroke();
    g.setLineDash([3, 5]); g.strokeStyle = '#ff6a1a'; g.lineWidth = 1;
    g.beginPath(); g.arc(cx, cy, 10 + thr * (R - 10), 0, Math.PI * 2); g.stroke(); g.setLineDash([]);
    ui.meter.style.width = `${lvl * 100}%`;
  }
  // detections
  S.ripples = S.ripples.filter((r) => t - r.t < 1600);
  for (const r of S.ripples) {
    const p = (t - r.t) / 1600;
    g.strokeStyle = CLS_COLOR[r.cls] || '#75726c';
    g.globalAlpha = 1 - p; g.lineWidth = 1.5 + r.s * 3;
    g.beginPath(); g.arc(cx, cy, 10 + p * (R - 10), 0, Math.PI * 2); g.stroke();
    if (r.seismic) { g.setLineDash([2, 4]); g.beginPath(); g.arc(cx, cy, 10 + p * (R - 10) * 0.82, 0, Math.PI * 2); g.stroke(); g.setLineDash([]); }
  }
  g.globalAlpha = 1;
  g.fillStyle = '#ff6a1a';
  g.fillRect(cx - 4, cy - 4, 8, 8);
  requestAnimationFrame(draw);
}

// ---------------- QR join ----------------
let scanStream = null;
$('#scan').addEventListener('click', async () => {
  ui.err.textContent = '';
  if (!window.jsQR) return (ui.err.textContent = 'QR scanner unavailable. Enter the code instead.');
  try {
    scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
  } catch {
    ui.err.textContent = 'Camera access is needed to scan. Enter the code instead.';
    return;
  }
  const video = $('#scanVideo');
  video.srcObject = scanStream;
  $('#scanner').hidden = false;
  await video.play().catch(() => {});
  const c = document.createElement('canvas');
  const g = c.getContext('2d', { willReadFrequently: true });
  const loop = () => {
    if (!scanStream) return;
    if (video.readyState >= 2 && video.videoWidth) {
      const w = 480, h = Math.round((video.videoHeight / video.videoWidth) * 480);
      c.width = w; c.height = h;
      g.drawImage(video, 0, 0, w, h);
      const r = window.jsQR(g.getImageData(0, 0, w, h).data, w, h, { inversionAttempts: 'dontInvert' });
      if (r && r.data && applyJoinCode(r.data)) return stopScan(true);
    }
    requestAnimationFrame(loop);
  };
  loop();
});
$('#scanClose').addEventListener('click', () => stopScan(false));

function stopScan(ok) {
  if (scanStream) scanStream.getTracks().forEach((t) => t.stop());
  scanStream = null;
  $('#scanner').hidden = true;
  if (ok) { navigator.vibrate?.(60); ui.go.focus(); }
}

function applyJoinCode(text) {
  try {
    const u = new URL(text);
    const site = u.searchParams.get('site');
    if (!site) return false;
    ui.code.value = site.toUpperCase();
    if (NATIVE) ui.server.value = u.origin;
    return true;
  } catch {
    if (/^[A-Z0-9]{4,8}$/i.test(text.trim())) { ui.code.value = text.trim().toUpperCase(); return true; }
    return false;
  }
}

if (!NATIVE && 'serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
