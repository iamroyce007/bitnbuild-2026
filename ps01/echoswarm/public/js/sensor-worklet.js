// Runs on the real-time audio thread. Per 128-frame block it extracts cheap edge features
// (RMS, zero-crossings, low/high band energy, peak) and can capture raw audio for ranging.
class SensorProcessor extends AudioWorkletProcessor {
  constructor() {
    super();
    const sr = sampleRate;
    this.aLow = Math.exp((-2 * Math.PI * 400) / sr); // one-pole low-pass @400 Hz
    this.aHigh = Math.exp((-2 * Math.PI * 3000) / sr); // one-pole low-pass @3 kHz (high = x - lp)
    this.lp = 0; this.lp3 = 0; this.prev = 0;
    this.BATCH = 4;
    this.reset();
    this.rec = null;
    this.port.onmessage = (e) => {
      if (e.data.cmd === 'record') this.rec = { buf: new Float32Array(e.data.frames), i: 0, start: -1 };
    };
  }
  reset() {
    this.n = 0;
    this.f0 = -1;
    this.rms = new Float32Array(this.BATCH);
    this.zcr = new Float32Array(this.BATCH);
    this.low = new Float32Array(this.BATCH);
    this.high = new Float32Array(this.BATCH);
    this.peak = new Float32Array(this.BATCH);
  }
  process(inputs) {
    const ch = inputs[0] && inputs[0][0];
    if (!ch) return true;
    if (this.f0 < 0) this.f0 = currentFrame;
    let ss = 0, zc = 0, lo = 0, hi = 0, pk = 0;
    for (let i = 0; i < ch.length; i++) {
      const x = ch[i];
      ss += x * x;
      if ((x >= 0) !== (this.prev >= 0)) zc++;
      this.prev = x;
      this.lp = this.aLow * this.lp + (1 - this.aLow) * x;
      this.lp3 = this.aHigh * this.lp3 + (1 - this.aHigh) * x;
      lo += this.lp * this.lp;
      const h = x - this.lp3;
      hi += h * h;
      const a = x < 0 ? -x : x;
      if (a > pk) pk = a;
    }
    const k = this.n;
    this.rms[k] = Math.sqrt(ss / ch.length);
    this.zcr[k] = zc / ch.length;
    this.low[k] = lo / ch.length;
    this.high[k] = hi / ch.length;
    this.peak[k] = pk;
    this.n++;
    if (this.n === this.BATCH) {
      this.port.postMessage({ type: 'feat', f: this.f0, bs: ch.length, rms: this.rms, zcr: this.zcr, low: this.low, high: this.high, peak: this.peak });
      this.reset();
    }
    if (this.rec) {
      const r = this.rec;
      if (r.start < 0) r.start = currentFrame;
      const m = Math.min(ch.length, r.buf.length - r.i);
      r.buf.set(ch.subarray(0, m), r.i);
      r.i += m;
      if (r.i >= r.buf.length) {
        this.port.postMessage({ type: 'rec', start: r.start, data: r.buf }, [r.buf.buffer]);
        this.rec = null;
      }
    }
    return true;
  }
}
registerProcessor('echoswarm-sensor', SensorProcessor);
