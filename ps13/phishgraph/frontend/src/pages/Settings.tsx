import { useState } from 'react';
import { PageTitle, Section } from '../components/ui';
import { Link } from 'react-router-dom';
import { api, clearKey, getKey, setKey } from '../lib/api';

export default function Settings() {
  const [key, setK] = useState(getKey());
  const [msg, setMsg] = useState('');
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setKey(key.trim());
    try {
      await api.statistics(1);
      setMsg('Saved. The key works.');
    } catch (x) {
      setMsg(x instanceof Error && /401/.test(x.message + (x as { status?: number }).status) ? 'Saved, but the server rejected this key.' : `Saved. Server check failed: ${x instanceof Error ? x.message : x}`);
    }
  };
  return (
    <>
      <PageTitle title="Settings" />
      <div className="max-w-xl space-y-5">
        <Section title="API key">
          <form onSubmit={save} className="space-y-3">
            <label className="block"><span className="label">X-API-Key</span>
              <input className="input mt-1 font-mono" type="password" autoComplete="off" value={key} onChange={(e) => setK(e.target.value)} /></label>
            <p className="text-[12px] text-muted">Stored only in this browser. Keys are configured on the server with the API_KEYS environment variable.</p>
            <button className="btn btn-primary">Save</button>
            {msg && <p className="text-[13px] text-muted" role="status">{msg}</p>}
          </form>
        </Section>
        <Section title="Chrome extension">
          <p className="text-[13px] text-muted">Download, install and connect it in three steps on the <Link to="/setup" className="text-accent hover:underline">Setup</Link> page.</p>
        </Section>
        <Section title="Disconnect this browser">
          <p className="mb-3 text-[13px] text-muted">Removes the stored key from this browser only.</p>
          <button className="btn" onClick={() => { clearKey(); window.location.href = '/'; }}>Disconnect</button>
        </Section>
      </div>
    </>
  );
}
