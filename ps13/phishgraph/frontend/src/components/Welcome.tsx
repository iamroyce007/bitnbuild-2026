import { useState } from 'react';
import { api, setKey } from '../lib/api';

/** Shown instead of the app when this browser has no working API key. */
export default function Welcome({ onConnected }: { onConnected: () => void }) {
  const [key, setK] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const connect = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr('');
    setKey(key.trim());
    try {
      await api.sampleStatus();
      onConnected();
    } catch (x) {
      setErr(x instanceof Error && /401|key/i.test(x.message) ? 'That key was not accepted. Check it and try again.' : 'Could not reach the server. Try again in a moment.');
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="grid min-h-full place-items-center px-5 py-10">
      <div className="w-full max-w-md">
        <div className="mb-6 flex items-center gap-3">
          <img src="/favicon.svg" alt="" width={36} height={36} />
          <div>
            <div className="text-[18px] font-semibold tracking-tight">PhishGraph</div>
            <div className="text-[13px] text-muted">Real-time phishing detection with explainable verdicts</div>
          </div>
        </div>
        <div className="card p-6">
          <h1 className="text-[17px] font-semibold">Connect this browser</h1>
          <p className="mt-1 text-[13px] text-muted">
            The easiest way is the <b className="text-ink">setup link</b> from whoever runs this PhishGraph server: open it once and this browser is connected.
          </p>
          <form onSubmit={connect} className="mt-5 space-y-3">
            <label className="block">
              <span className="label">Or paste the access key</span>
              <input className="input mt-1 font-mono" type="password" autoComplete="off" value={key} onChange={(e) => setK(e.target.value)} autoFocus />
            </label>
            {err && <p role="alert" className="text-[13px] text-block">{err}</p>}
            <button className="btn btn-primary w-full" disabled={!key.trim() || busy}>{busy ? 'Connecting…' : 'Connect'}</button>
          </form>
          <p className="mt-4 text-[12px] text-faint">Running your own server? The key is the <code className="font-mono">API_KEYS</code> value you configured. It is stored only in this browser.</p>
        </div>
      </div>
    </div>
  );
}
