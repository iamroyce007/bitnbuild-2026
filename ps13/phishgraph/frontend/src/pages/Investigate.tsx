import { ChevronDown, Globe, Radar, ShieldCheck } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import GraphView, { GraphLegend, NodePanel } from '../components/GraphView';
import InvestigationInput, { EXAMPLES } from '../components/investigation/InvestigationInput';
import InvestigationLoader, { STAGES } from '../components/investigation/InvestigationLoader';
import ThreatTimeline from '../components/investigation/ThreatTimeline';
import { CopyButton, ErrorState, SeverityBadge, SEVERITY, StatusBadge, ThreatScore } from '../components/kit';
import ReportView from '../components/ReportView';
import { Section } from '../components/ui';
import { api } from '../lib/api';
import type { GraphData, GraphNode, Report } from '../lib/types';

const ENGINE: Record<string, string> = { nlp: 'Language (NLP)', url: 'URL structure model', brand: 'Brand impersonation', metadata: 'Sender & headers', threat_intelligence: 'Threat intelligence', graph: 'Infrastructure overlap' };

function Fact({ label, value, mono = true }: { label: string; value: React.ReactNode; mono?: boolean }) {
  if (value == null || value === '' || value === false) return null;
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-line/60 py-1.5 last:border-0">
      <dt className="shrink-0 text-[12px] text-faint">{label}</dt>
      <dd className={`min-w-0 break-all text-right text-[12.5px] ${mono ? 'font-mono' : ''}`}>{value}</dd>
    </div>
  );
}

export default function Investigate() {
  const [params, setParams] = useSearchParams();
  const [url, setUrl] = useState(params.get('url') || '');
  const [target, setTarget] = useState('');
  const [job, setJob] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const [rep, setRep] = useState<Report | null>(null);
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [node, setNode] = useState<GraphNode | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [full, setFull] = useState(false);
  const timer = useRef<number>();
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => () => window.clearTimeout(timer.current), []);
  // "/" focuses the investigation bar
  useEffect(() => {
    const on = (e: KeyboardEvent) => { if (e.key === '/' && !(e.target as HTMLElement)?.closest('input,textarea,select,[contenteditable]')) { e.preventDefault(); input.current?.focus(); } };
    window.addEventListener('keydown', on);
    return () => window.removeEventListener('keydown', on);
  }, []);

  const poll = async (id: string, n = 0) => {
    try {
      const j = await api.job(id);
      setTick(Math.min(n, STAGES.length - 1));
      if (j.status === 'done') {
        const r = j.result as unknown as Report & { error?: string };
        if (r?.error) { setErr(r.error); setJob(null); return; }
        setTick(STAGES.length);
        setRep(r);
        setJob(null);
        try { setGraph(await api.graphDetection(r.detection_id, 3)); } catch { setGraph({ nodes: [], edges: [] }); }
        return;
      }
      if (j.status === 'failed') { setErr(j.error || 'The investigation did not complete.'); setJob(null); return; }
      timer.current = window.setTimeout(() => poll(id, n + 1), 600);
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)); setJob(null); }
  };
  const run = async (q: string) => {
    const t = /^[a-z]+:\/\//i.test(q) ? q : `https://${q}`;
    setErr(null); setRep(null); setGraph(null); setNode(null); setTick(0); setTarget(q); setFull(false);
    try {
      const { job_id } = await api.investigate(t);
      setJob(job_id);
      poll(job_id);
    } catch (x) { setErr(x instanceof Error ? x.message : String(x)); }
  };
  // opened from the command palette or landing page: /investigate?url=...
  useEffect(() => {
    const u = params.get('url');
    if (u) { setUrl(u); run(u); setParams({}, { replace: true }); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params]);

  const u = rep?.urls[0];
  const e = (u?.enrichment || {}) as Record<string, any>;
  const status = job ? { label: 'Live analysis', tone: 'accent' as const, live: true } : err ? { label: 'Failed', tone: 'block' as const, live: false }
    : rep ? { label: 'Analysis complete', tone: 'allow' as const, live: false } : { label: 'Ready', tone: 'faint' as const, live: false };
  const factors = rep ? Object.entries(ENGINE).map(([k, label]) => ({ label, value: rep.scores[k] ?? null })) : [];

  return (
    <div className="space-y-5">
      {/* header: breadcrumb + status */}
      <div className="flex flex-wrap items-end justify-between gap-3 border-b border-line pb-4">
        <div className="min-w-0">
          <nav aria-label="Breadcrumb" className="eyebrow mb-1.5 flex items-center gap-1.5">
            <Link to="/investigate" onClick={() => { setRep(null); setErr(null); setTarget(''); }} className="hover:text-ink">Investigations</Link>
            {target && <><span aria-hidden="true">/</span><span className="truncate text-muted" aria-current="page">{target}</span></>}
          </nav>
          <h1 className="text-[22px] font-semibold tracking-tight">{target ? <span className="font-mono text-[20px]">{target}</span> : 'New investigation'}</h1>
        </div>
        <StatusBadge {...status} />
      </div>

      <InvestigationInput ref={input} value={url} onChange={setUrl} onSubmit={run} busy={!!job} size="lg" showExamples={!rep && !job} autoFocus={!target} />

      {job && <InvestigationLoader step={tick} target={target} />}
      {err && !job && <ErrorState detail={err} onRetry={() => run(target)} />}

      {!job && !err && !rep && (
        <div className="card relative overflow-hidden p-8 text-center">
          <Radar className="mx-auto mb-3 size-9 text-accent" strokeWidth={1.25} />
          <div className="font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-accent">Start an investigation</div>
          <p className="mx-auto mt-2 max-w-lg text-[14px] text-muted">Enter a domain, URL or IP address. PhishGraph resolves it, checks registration, certificate and network, correlates live threat intelligence and maps it against known phishing infrastructure.</p>
          <div className="mt-5 flex flex-wrap justify-center gap-2">
            {EXAMPLES.map((x) => <button key={x} className="btn font-mono text-[12px]" onClick={() => { setUrl(x); run(x); }}>{x}</button>)}
          </div>
          <p className="mt-4 text-[11.5px] text-faint">Private and internal addresses are refused. Only DNS, RDAP and the TLS handshake touch the target; page content is never fetched.</p>
        </div>
      )}

      {rep && (
        <>
          <div className="grid grid-cols-[minmax(0,1fr)] gap-4 lg:grid-cols-[280px_minmax(0,1fr)] 2xl:grid-cols-[290px_minmax(0,1fr)_330px]">
            {/* LEFT: entity */}
            <div className="stagger space-y-4">
              <Section title="Entity">
                <div className="flex items-start gap-3">
                  <span className="grid size-10 shrink-0 place-items-center rounded-md border border-line-strong bg-surface-2"><Globe className="size-5 text-accent" strokeWidth={1.75} /></span>
                  <div className="min-w-0">
                    <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-faint">Domain</div>
                    <div className="flex items-start gap-1"><span className="break-all font-mono text-[13px]">{u?.host || target}</span>{u?.host && <CopyButton value={u.host} />}</div>
                  </div>
                </div>
                <div className="mt-3 flex items-center justify-between rounded-md border border-line bg-surface-2/50 px-3 py-2">
                  <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-faint">Threat level</span>
                  <SeverityBadge severity={SEVERITY[rep.decision]} size="md" />
                </div>
                <dl className="mt-3">
                  <Fact label="Registrable" value={u?.registrable} />
                  <Fact label="Official brand" value={u?.brand?.official} mono={false} />
                  <Fact label="Tranco rank" value={u?.brand?.tranco_rank?.toLocaleString()} />
                  <Fact label="Domain age" value={e.rdap?.age_days != null ? `${e.rdap.age_days} days` : null} />
                  <Fact label="Registrar" value={e.rdap?.registrar} mono={false} />
                  <Fact label="IP addresses" value={(e.dns?.a || []).slice(0, 3).join(', ')} />
                  <Fact label="Network" value={e.asn?.[0] ? `${e.asn[0].asn} ${e.asn[0].name || ''}` : null} />
                  <Fact label="Country" value={e.asn?.[0]?.country} />
                  <Fact label="Nameservers" value={(e.dns?.ns || []).slice(0, 2).join(', ')} />
                  <Fact label="TLS issuer" value={e.tls?.issuer} mono={false} />
                  <Fact label="URL model" value={u?.ml_probability != null ? `${Math.round(u.ml_probability * 100)}% phishing-like` : null} />
                  <Fact label="Campaign" value={rep.campaign?.id ? <Link className="text-accent hover:underline" to={`/campaigns/${rep.campaign.id}`}>{rep.campaign.id}</Link> : null} />
                </dl>
                {u?.brand?.findings?.[0] && <p className="mt-3 rounded-md border border-block/30 bg-block/5 px-3 py-2 text-[12px] text-ink">{u.brand.findings[0].evidence}</p>}
                {u?.trusted && <p className="mt-3 flex items-center gap-2 text-[12px] text-muted"><ShieldCheck className="size-4 text-allow" />Official or long-established site.</p>}
              </Section>
            </div>

            {/* CENTER: graph */}
            <div className="min-w-0 space-y-4 2xl:order-none">
              <Section title="Infrastructure graph" right={<span className="font-mono text-[11px] text-faint">{graph ? `${graph.nodes.length} entities · ${graph.edges.length} links` : 'mapping…'}</span>}>
                {graph ? <GraphView data={graph} height={460} onSelect={setNode} selectedId={node?.id} /> : <div className="skeleton h-[460px]" />}
                <div className="mt-3"><GraphLegend /></div>
              </Section>
              {node && <Section title="Selected entity"><NodePanel node={node} data={graph} onSelect={setNode} /></Section>}
            </div>

            {/* RIGHT: score, evidence, intelligence, timeline */}
            <div className="stagger space-y-4 lg:col-span-2 lg:grid lg:grid-cols-2 lg:gap-4 lg:space-y-0 2xl:col-span-1 2xl:block 2xl:space-y-4">
              <Section title="Threat score"><ThreatScore score={rep.risk_score} decision={rep.decision} factors={factors} /></Section>
              <Section title="Evidence">
                <ul className="discover space-y-2">
                  {rep.reasons.slice(0, 7).map((r, i) => (
                    <li key={i} className="grid grid-cols-[3px_1fr] gap-2.5 text-[12.5px]">
                      <span className="rounded-full" style={{ background: r.weight >= 0.8 ? 'var(--color-block)' : r.weight >= 0.4 ? 'var(--color-quarantine)' : 'var(--color-line-strong)' }} aria-hidden="true" />
                      <span><span className="font-mono text-[10px] uppercase tracking-[0.14em] text-faint">{r.category}</span><br />{r.text}</span>
                    </li>
                  ))}
                </ul>
                {!rep.reasons.length && <p className="text-[12.5px] text-muted">No risk evidence was found.</p>}
              </Section>
              <Section title="Intelligence sources">
                <ul className="space-y-1.5">
                  {rep.threat_intel.sources.map((s) => (
                    <li key={s.source} className="flex items-center justify-between gap-2 text-[12px]">
                      <span className="font-mono">{s.display || s.source}</span>
                      <span className={`font-mono text-[10.5px] tracking-[0.1em] ${s.verdict === 'malicious' ? 'text-block' : s.status === 'ok' ? 'text-muted' : 'text-faint'}`}>
                        {s.verdict === 'malicious' ? 'MALICIOUS' : s.status === 'ok' ? (s.verdict || 'NO MATCH').toUpperCase() : s.status.replace(/_/g, ' ').toUpperCase()}
                      </span>
                    </li>
                  ))}
                </ul>
              </Section>
              <Section title="Timeline"><ThreatTimeline report={rep} /></Section>
            </div>
          </div>

          <section className="card">
            <button className="flex w-full items-center justify-between px-4 py-3 text-left" onClick={() => setFull((f) => !f)} aria-expanded={full}>
              <span className="text-[14px] font-semibold">Full explainable report</span>
              <ChevronDown className={`size-4 text-faint transition-transform duration-200 ${full ? 'rotate-180' : ''}`} />
            </button>
            {full && <div className="border-t border-line p-4"><ReportView r={rep} /></div>}
          </section>
        </>
      )}
    </div>
  );
}
