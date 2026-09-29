import { ErrorBox, Loading, PageTitle, Section, Stat } from '../components/ui';
import { api } from '../lib/api';
import { useApi } from '../lib/useApi';

function parseMetrics(text: string) {
  return text.split('\n').filter((l) => l && !l.startsWith('#')).map((l) => {
    const m = l.match(/^([a-z_]+)(\{[^}]*\})?\s+([\d.]+)$/);
    return m ? { name: m[1], labels: m[2] || '', value: Number(m[3]) } : null;
  }).filter(Boolean) as { name: string; labels: string; value: number }[];
}

export default function Health() {
  const ready = useApi(() => api.ready());
  const metrics = useApi(() => api.metrics());
  if (ready.error) return <ErrorBox error={ready.error} />;
  if (!ready.data) return <Loading />;
  const r = ready.data as Record<string, string | number | boolean>;
  const rows = metrics.data ? parseMetrics(metrics.data) : [];
  return (
    <>
      <PageTitle title="System health" sub="Readiness of every dependency and the Prometheus metrics exposed at /metrics." right={<button className="btn" onClick={() => { ready.reload(); metrics.reload(); }}>Refresh</button>} />
      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="API" value={r.ready ? 'Ready' : 'Starting'} color={r.ready ? 'var(--color-allow)' : 'var(--color-flag)'} />
        <Stat label="Database" value={String(r.database)} />
        <Stat label="Cache" value={String(r.cache)} />
        <Stat label="Graph store" value={String(r.graph)} />
        <Stat label="Queue depth" value={String(r.queue_depth)} />
        <Stat label="Model warm-up" value={`${r.warmup_s}s`} />
      </div>
      <Section title="Metrics" flush>
        {!metrics.data ? <Loading /> : (
          <div className="max-h-[560px] overflow-auto">
            <table className="tbl">
              <thead><tr><th>Metric</th><th>Labels</th><th className="text-right">Value</th></tr></thead>
              <tbody>{rows.map((m, i) => <tr key={i}><td className="font-mono text-[12px]">{m.name}</td><td className="font-mono text-[12px] text-muted">{m.labels}</td><td className="text-right font-mono">{m.value}</td></tr>)}</tbody>
            </table>
          </div>
        )}
      </Section>
    </>
  );
}
