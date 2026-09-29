import { useState } from 'react';
import GraphView, { GraphLegend, NodePanel, TYPE_LABEL } from '../components/GraphView';
import { ErrorBox, Loading, PageTitle, Section } from '../components/ui';
import { api } from '../lib/api';
import type { GraphData, GraphNode } from '../lib/types';
import { useApi } from '../lib/useApi';

export default function Graph() {
  const overview = useApi(() => api.graphOverview());
  const [domain, setDomain] = useState('');
  const [focused, setFocused] = useState<GraphData | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [node, setNode] = useState<GraphNode | null>(null);
  const [showTable, setShowTable] = useState(false);
  const data = focused || overview.data;

  const lookup = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    try { setFocused(await api.graphDomain(domain.trim().toLowerCase())); setNode(null); } catch (x) { setErr(x); }
  };
  const byType = data ? Object.entries(data.nodes.reduce<Record<string, number>>((a, n) => ({ ...a, [n.type]: (a[n.type] || 0) + 1 }), {})) : [];
  const label = (id: string) => data?.nodes.find((n) => n.id === id)?.label || id;
  return (
    <>
      <PageTitle title="Threat graph" sub="Emails, links, domains and the infrastructure behind them. Shared IPs, certificates and nameservers connect campaigns." />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <form onSubmit={lookup} className="flex gap-2">
          <label className="sr-only" htmlFor="d">Domain</label>
          <input id="d" className="input w-72 font-mono" placeholder="focus on a domain…" value={domain} onChange={(e) => setDomain(e.target.value)} />
          <button className="btn" disabled={!domain.trim()}>Focus</button>
        </form>
        {focused && <button className="btn btn-ghost" onClick={() => { setFocused(null); setNode(null); }}>Back to overview</button>}
        <span className="ml-auto font-mono text-[12px] text-faint">{byType.map(([t, n]) => `${n} ${TYPE_LABEL[t] || t}`).join(' · ')}</span>
      </div>
      {err && <div className="mb-4"><ErrorBox error={err} /></div>}
      {overview.error ? <ErrorBox error={overview.error} /> : !data ? <Loading /> : (
        <div className="grid grid-cols-[minmax(0,1fr)] gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
          <Section title={focused ? `Neighbourhood of ${domain}` : 'Campaign and high-risk neighbourhoods'}>
            <GraphView data={data} height={600} onSelect={setNode} selectedId={node?.id} />
            <div className="mt-3"><GraphLegend /></div>
          </Section>
          <div className="space-y-5">
            <Section title="Selected node"><NodePanel node={node} /></Section>
            <Section title="Relationships as a table" right={<button className="text-[12px] text-accent hover:underline" onClick={() => setShowTable((s) => !s)} aria-expanded={showTable}>{showTable ? 'Hide' : 'Show'}</button>} flush>
              {showTable ? (
                <div className="max-h-96 overflow-auto">
                  <table className="tbl"><tbody>
                    {data.edges.slice(0, 300).map((e, i) => (
                      <tr key={i}><td className="break-all font-mono text-[11px]">{label(e.source)}</td><td className="font-mono text-[10px] text-faint">{e.rel}</td><td className="break-all font-mono text-[11px]">{label(e.target)}</td></tr>
                    ))}
                  </tbody></table>
                </div>
              ) : <p className="p-4 text-[13px] text-muted">{data.edges.length} relationships. A tabular view for screen readers and exact inspection.</p>}
            </Section>
          </div>
        </div>
      )}
    </>
  );
}
