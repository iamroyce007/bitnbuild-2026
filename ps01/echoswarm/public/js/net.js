// Shared: resilient WebSocket + NTP-style clock sync to the server.
export function localNow() {
  return performance.timeOrigin + performance.now();
}

export class Link {
  constructor(hello, onMessage, onStatus, base) {
    this.base = base || '';
    this.hello = hello;
    this.onMessage = onMessage;
    this.onStatus = onStatus || (() => {});
    this.samples = [];
    this.offset = 0; // serverTime = localNow() + offset
    this.rtt = null;
    this.backoff = 500;
    this.connect();
  }
  get url() {
    if (this.base) return `${this.base.replace(/^http/, 'ws').replace(/\/$/, '')}/ws`;
    return `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`;
  }
  close() { this.closed = true; try { this.ws.close(); } catch {} }
  connect() {
    const ws = (this.ws = new WebSocket(this.url));
    ws.onopen = () => {
      this.backoff = 500;
      this.send(this.hello);
      this.onStatus(true);
      this.burstSync();
      clearInterval(this.syncTimer);
      this.syncTimer = setInterval(() => this.sync(), 4000);
    };
    ws.onmessage = (e) => {
      let m;
      try { m = JSON.parse(e.data); } catch { return; }
      if (m.type === 'syncR') return this.onSync(m);
      this.onMessage(m);
    };
    ws.onclose = () => {
      if (this.closed) return;
      this.onStatus(false);
      clearInterval(this.syncTimer);
      setTimeout(() => this.connect(), this.backoff);
      this.backoff = Math.min(8000, this.backoff * 1.7);
    };
    ws.onerror = () => ws.close();
  }
  send(m) {
    if (this.ws && this.ws.readyState === 1) this.ws.send(JSON.stringify(m));
  }
  sync() { this.send({ type: 'sync', t0: localNow() }); }
  burstSync() { for (let i = 0; i < 8; i++) setTimeout(() => this.sync(), i * 120); }
  onSync(m) {
    const t1 = localNow();
    const rtt = t1 - m.t0;
    const off = m.ts - (m.t0 + t1) / 2;
    this.samples.push({ rtt, off });
    if (this.samples.length > 16) this.samples.shift();
    // trust the lowest-latency exchanges most
    const best = [...this.samples].sort((a, b) => a.rtt - b.rtt).slice(0, 4);
    this.offset = best.reduce((a, s) => a + s.off, 0) / best.length;
    this.rtt = best[0].rtt;
  }
  serverNow() { return localNow() + this.offset; }
  toLocal(serverT) { return serverT - this.offset; }
}

export function qs(name) {
  return new URLSearchParams(location.search).get(name);
}

export function store(key, val) {
  try {
    if (val === undefined) return localStorage.getItem(key);
    localStorage.setItem(key, val);
  } catch { return null; }
}
