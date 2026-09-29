import { Network, Search, X } from 'lucide-react';
import { useState } from 'react';
import GraphView, { GraphLegend, NodePanel, TYPE_LABEL } from '../components/GraphView';
import { StatusBadge, toast } from '../components/kit';
import { ErrorBox, Loading, PageTitle, Section } from '../components/ui';
import { api } from '../lib/api';
import type { GraphData, GraphNode } from '../lib/types';
import { useApi } from '../lib/useApi';

/** Merge an expansion into the current graph (dedupe nodes by id, edges by source/target/rel). */
function merge(a: GraphData, b: GraphData): GraphData {
  const ids = new Set(a.nodes.map((n) => n.id));
  const ek = (e: GraphData['edges'][number]) => `${e.source}|${e.target}|${e.rel}`;
  const eks = new Set(a.edges.map(ek));
  return { nodes: [...a.nodes, ...b.nodes.filter((n) => !ids.has(n.id))], edges: [...a.edges, ...b.edges.filter((e) => !eks.has(ek(e)))] };
}

export default function Graph() {
  const overview = useApi(() => api.graphOverview());
  const [domain, setDomain] = useState('');
  const [focused, setFocused] = useState<GraphData | null>(null);
  const [focusLabel, setFocusLabel] = useState('');
  const [err, setErr] = useState<unknown>(null);
  const [node, setNode] = useState<GraphNode | null>(null);
  const [showTable, setShowTable] = useState(false);
  const [expanding, setExpanding] = useState(false);
  const data = focused || overview.data;

  const lookup = async (e: React.FormEvent) => {
    e.preventDefault();
    const d = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!d) return;
    setErr(null);
    try { setFocused(await api.graphDomain(d)); setFocusLabel(d); setNode(null); } catch (x) { setErr(x); }
  };
  // double-click: pull the real neighbourhood of that entity and merge it in
  const expand = async (n: GraphNode) => {
    if (!data) return;
    const key = String(n.id).split(':').slice(1).join(':');
    const fetcher = n.type === 'domain' ? () => api.graphDomain(key) : n.type === 'email' ? () => api.graphDetection(key, 2) : null;
    if (!fetcher) { toast(`${TYPE_LABEL[n.type] || n.type} nodes expand through their domain or message`, 'info'); return; }
    setExpanding(true);
    try {
      const more = await fetcher();
      const before = data.nodes.length;
      const next = merge(data, more);
      setFocused(next);
      setFocusLabel(focusLabel || 'expanded view');
      toast(`${next.nodes.length - before} related entities discovered`);
    } catch { toast('Could not expand this entity', 'error'); }
    finally { setExpanding(false); }
  };
  const byType = data ? Object.entries(data.nodes.reduce<Record<string, number>>((a, n) => ({ ...a, [n.type]: (a[n.type] || 0) + 1 }), {})).sort((a, b) => b[1] - a[1]) : [];
  const label = (id: string) => data?.nodes.find((n) => n.id === id)?.label || id;
  const bad = data?.nodes.filter((n) => n.malicious).length || 0;
  return (
    <>
      <PageTitle title="Threat graph" sub="Messages, links, domains and the infrastructure behind them, including live phishing feeds. Double-click an entity to expand it."
        right={<StatusBadge label={expanding ? 'Expanding' : focused ? 'Focused view' : 'Live infrastructure'} tone={expanding ? 'flag' : 'accent'} live={!focused || expanding} />} />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <form onSubmit={lookup} className="relative flex w-full max-w-md gap-2">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-faint" />
          <label className="sr-only" htmlFor="d">Focus on a domain</label>
          <input id="d" className="input pl-9 font-mono" inputMode="url" autoCapitalize="none" spellCheck={false} placeholder="Focus on a domain, e.g. paypa1-billing.com" value={domain} onChange={(e) => setDomain(e.target.value)} />
          <button className="btn shrink-0" disabled={!domain.trim()}>Focus</button>
        </form>
        {focused && <button className="btn btn-ghost" onClick={() => { setFocused(null); setFocusLabel(''); setNode(null); }}><X className="size-3.5" />Back to overview</button>}
        <div className="ml-auto flex flex-wrap gap-x-3 gap-y-1 font-mono text-[11px] text-faint">
          {byType.slice(0, 7).map(([t, n]) => <span key={t}><span className="text-ink">{n}</span> {TYPE_LABEL[t] || t}</span>)}
          {bad > 0 && <span><span className="text-block">{bad}</span> known bad</span>}
        </div>
      </div>
      {err ? <div className="mb-4"><ErrorBox error={err} /></div> : null}
      {overview.error ? <ErrorBox error={overview.error} /> : !data ? <Loading /> : (
        <div className="grid grid-cols-[minmax(0,1fr)] gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
          <Section title={focused ? <>Neighbourhood of <span className="font-mono">{focusLabel}</span></> : 'Campaigns, targeted brands and abused platforms'}
            right={<Network className="size-4 text-faint" />}>
            <GraphView data={data} height={620} onSelect={setNode} selectedId={node?.id} onExpand={expand} />
            <div className="mt-3"><GraphLegend /></div>
          </Section>
          <div className="space-y-5">
            <Section title="Entity details"><NodePanel node={node} data={data} onSelect={setNode} /></Section>
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
