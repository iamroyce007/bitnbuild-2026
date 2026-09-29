import { useState } from 'react';
import { DemoTag, ErrorBox, Loading, PageTitle, Section, ago } from '../components/ui';
import { api } from '../lib/api';
import { useApi } from '../lib/useApi';

const STATE_COLOR: Record<string, string> = { online: 'var(--color-allow)', degraded: 'var(--color-flag)', offline: 'var(--color-block)', not_configured: 'var(--color-faint)', disabled: 'var(--color-faint)' };

export default function Intel() {
  const prov = useApi(() => api.providers());
  const feed = useApi(() => api.threatFeed('?limit=100'));
  const [ioc, setIoc] = useState({ type: 'domain', value: '' });
  const [msg, setMsg] = useState('');
  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    const r = await api.addIoc(ioc.type, ioc.value.trim());
    setMsg(r.added ? 'Indicator added and marked malicious in the graph.' : 'Already present.');
    setIoc({ ...ioc, value: '' });
    feed.reload();
  };
  return (
    <>
      <PageTitle title="Threat intelligence" sub="External providers are optional and off until keys are set. Local feeds are ingested on a schedule, never queried per message." />
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
        <Section title="Providers" flush>
          {prov.error ? <div className="p-4"><ErrorBox error={prov.error} /></div> : !prov.data ? <Loading /> : (
            <table className="tbl">
              <thead><tr><th>Provider</th><th>State</th><th>Indicators</th><th className="text-right">Calls</th><th className="text-right">Errors</th><th className="text-right">Avg ms</th></tr></thead>
              <tbody>
                {prov.data.providers.map((p) => (
                  <tr key={p.name}>
                    <td className="font-mono text-[12px]">{p.name}{!p.external && <span className="ml-2 text-faint">(local)</span>}</td>
                    <td><span className="inline-flex items-center gap-1.5 font-mono text-[11px]" style={{ color: STATE_COLOR[p.state] }}><span className="size-1.5 rounded-full" style={{ background: STATE_COLOR[p.state] }} />{p.state.replace('_', ' ').toUpperCase()}</span>
                      {p.last_error && <div className="text-[11px] text-faint">{p.last_error}</div>}</td>
                    <td className="font-mono text-[11px] text-muted">{p.supports.join(', ')}</td>
                    <td className="text-right font-mono">{p.calls}</td>
                    <td className="text-right font-mono">{p.errors}</td>
                    <td className="text-right font-mono">{p.avg_latency_ms ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Section>
        <div className="space-y-5">
          <Section title="Add indicator">
            <form onSubmit={add} className="flex gap-2">
              <label className="sr-only" htmlFor="t">Type</label>
              <select id="t" className="input w-28" value={ioc.type} onChange={(e) => setIoc({ ...ioc, type: e.target.value })}>
                {['domain', 'url', 'ip', 'hash'].map((t) => <option key={t}>{t}</option>)}
              </select>
              <label className="sr-only" htmlFor="v">Value</label>
              <input id="v" className="input font-mono" value={ioc.value} onChange={(e) => setIoc({ ...ioc, value: e.target.value })} placeholder="evil-login.xyz" />
              <button className="btn" disabled={!ioc.value.trim()}>Add</button>
            </form>
            {msg && <p className="mt-2 text-[12px] text-muted" role="status">{msg}</p>}
          </Section>
          <Section title="Feed collectors">
            {!feed.data ? <Loading /> : (
              <dl className="grid grid-cols-[1fr_auto] gap-y-1.5 text-[13px]">
                {Object.entries(feed.data.counts).map(([k, v]) => <div key={k} className="contents"><dt className="font-mono text-muted">{k}</dt><dd className="text-right font-mono">{v}</dd></div>)}
                {Object.entries(feed.data.feeds).map(([k, v]) => <div key={`s${k}`} className="contents"><dt className="font-mono text-faint">{k} last run</dt><dd className="text-right font-mono text-[12px] text-faint">{String(v.status)}</dd></div>)}
              </dl>
            )}
          </Section>
        </div>
      </div>
      <Section title="Local indicators (latest 100)" className="mt-5" flush>
        {!feed.data ? <Loading /> : (
          <div className="max-h-[480px] overflow-auto">
            <table className="tbl">
              <thead><tr><th className="w-20">Type</th><th>Value</th><th className="w-36">Source</th><th className="w-28 text-right">Added</th></tr></thead>
              <tbody>
                {feed.data.iocs.map((i, n) => (
                  <tr key={n}><td className="font-mono text-[12px] text-muted">{i.type}</td><td className="break-all font-mono text-[12px]">{i.value}</td>
                    <td className="font-mono text-[12px]">{i.source} {i.demo && <DemoTag />}</td><td className="text-right font-mono text-[12px] text-faint">{ago(i.first_seen)}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </>
  );
}
