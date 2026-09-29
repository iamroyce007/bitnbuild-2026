import { useEffect } from 'react';
import { useSample } from '../App';
import { Link } from 'react-router-dom';
import { useLive } from '../App';
import { Histogram, StackedBars } from '../components/charts';
import DetectionTable from '../components/DetectionTable';
import { DECISION_COLOR, DemoTag, ErrorBox, Loading, PageTitle, Section, Stat } from '../components/ui';
import { api } from '../lib/api';
import { useApi } from '../lib/useApi';

export default function Overview() {
  const stats = useApi(() => api.statistics(24));
  const recent = useApi(() => api.detections('?limit=8'));
  const camps = useApi(() => api.campaigns());
  const { events, paused } = useLive();
  const sample = useSample();
  useEffect(() => {
    const f = () => { stats.reload(); recent.reload(); camps.reload(); };
    window.addEventListener('phishgraph:data-changed', f);
    return () => window.removeEventListener('phishgraph:data-changed', f);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!paused && events[0]?.event === 'new_detection') {
      stats.reload();
      recent.reload();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [events[0]]);

  if (stats.error) return <ErrorBox error={stats.error} />;
  const s = stats.data;
  const by = s?.by_decision || {};
  const total24 = Object.values(by).reduce((a, b) => a + (b || 0), 0);
  return (
    <>
      <PageTitle title="Overview" sub="Last 24 hours of analysed messages and links" right={<Link to="/analyze" className="btn btn-primary">Analyze a message</Link>} />
      {s && s.total_detections === 0 ? (
        <section className="card max-w-3xl p-6">
          <h2 className="text-[18px] font-semibold"><span className="hl">Nothing analysed yet</span></h2>
          <p className="mt-1 text-[13px] text-muted">PhishGraph is running and already pulling real phishing indicators from the public OpenPhish feed. Give it something to look at:</p>
          <div className="stagger mt-5 grid gap-3 sm:grid-cols-3">
            <Link to="/analyze" className="card card-hover block p-4"><div className="font-medium">Analyze a message</div><div className="mt-1 text-[12px] text-muted">Paste an email, SMS or WhatsApp text, or a link.</div></Link>
            <Link to="/setup" className="card card-hover block p-4"><div className="font-medium">Install the extension</div><div className="mt-1 text-[12px] text-muted">Checks pages and Gmail messages as you browse.</div></Link>
            <button onClick={sample.load} disabled={sample.busy} className="card card-hover block p-4 text-left"><div className="font-medium">{sample.busy ? 'Loading…' : 'Load sample data'}</div><div className="mt-1 text-[12px] text-muted">27 labelled examples to explore every page. Removable.</div></button>
          </div>
        </section>
      ) : !s ? <Loading /> : (
        <div className="stagger space-y-5">
          <div className="stagger grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            <Stat label="Analysed (24 h)" value={total24} sub={`${s.total_detections} all time`} />
            <Stat label="Blocked" value={by.BLOCK || 0} color={DECISION_COLOR.BLOCK} />
            <Stat label="Quarantined" value={by.QUARANTINE || 0} color={DECISION_COLOR.QUARANTINE} />
            <Stat label="Flagged" value={by.FLAG || 0} color={DECISION_COLOR.FLAG} />
            <Stat label="Campaigns" value={s.campaigns} sub={`${s.threat_feed_size} feed indicators`} />
            <Stat label="Avg analysis" value={`${s.avg_latency_ms}`} sub="milliseconds" />
          </div>
          <div className="grid grid-cols-[minmax(0,1fr)] gap-5 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
            <Section title="Detections per hour"><StackedBars data={s.timeseries} /></Section>
            <Section title="Risk distribution"><Histogram bins={s.risk_histogram} />
              <p className="mt-3 text-[12px] text-muted">Thresholds: flag 30 · quarantine 60 · block 85.</p>
            </Section>
          </div>
          <div className="grid grid-cols-[minmax(0,1fr)] gap-5 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
            <Section title="Latest detections" right={<Link to="/feed" className="text-[12px] text-accent hover:underline">Live feed</Link>} flush>
              {recent.data ? <DetectionTable rows={recent.data} compact /> : <Loading />}
            </Section>
            <Section title="Active campaigns" right={<Link to="/campaigns" className="text-[12px] text-accent hover:underline">All</Link>} flush>
              {!camps.data ? <Loading /> : !camps.data.length ? <p className="p-4 text-[13px] text-muted">No campaigns yet.</p> : (
                <ul className="divide-y divide-line">
                  {camps.data.slice(0, 6).map((c) => (
                    <li key={c.id}>
                      <Link to={`/campaigns/${c.id}`} className="block px-4 py-3 hover:bg-surface-2">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-[12px] text-muted">{c.id}</span>
                          {c.demo && <DemoTag />}
                        </div>
                        <div className="mt-0.5 text-[13px]">{c.name}</div>
                        <div className="mt-1 font-mono text-[11px] text-faint">{c.stats.emails ?? 0} messages · {c.stats.domains ?? 0} domains · {c.stats.ips ?? 0} IPs</div>
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </Section>
          </div>
          <p className="text-[12px] text-faint">Graph store: {s.graph.backend} · {s.graph.nodes.toLocaleString()} nodes · {s.graph.edges.toLocaleString()} relationships</p>
        </div>
      )}
    </>
  );
}
