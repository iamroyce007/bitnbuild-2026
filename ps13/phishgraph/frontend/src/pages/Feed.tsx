import { useEffect, useMemo, useState } from 'react';
import { useLive } from '../App';
import DetectionTable from '../components/DetectionTable';
import { ErrorBox, Icon, Loading, PageTitle } from '../components/ui';
import { api } from '../lib/api';
import type { DetectionSummary } from '../lib/types';
import { useApi } from '../lib/useApi';

const FILTERS = ['ALL', 'BLOCK', 'QUARANTINE', 'FLAG', 'ALLOW'] as const;

export default function Feed() {
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>('ALL');
  const { data, error, reload } = useApi(() => api.detections(`?limit=100${filter === 'ALL' ? '' : `&decision=${filter}`}`), [filter]);
  const { events, paused, setPaused, state } = useLive();
  const [updated, setUpdated] = useState(new Date());
  const [pending, setPending] = useState(0);

  useEffect(() => {
    const e = events[0];
    if (!e || !['new_detection', 'detection_updated'].includes(e.event)) return;
    if (paused) setPending((n) => n + 1);
    else { reload(); setUpdated(new Date()); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [events[0]]);

  const rows: DetectionSummary[] = useMemo(() => data || [], [data]);
  const lastEvent = events.find((e) => e.event === 'new_detection');
  return (
    <>
      <PageTitle title="Live detections" sub={<>Updates arrive as messages are analysed ({state}). Last refresh {updated.toLocaleTimeString()}.</>}
        right={
          <button className="btn" onClick={() => { if (paused) { setPending(0); reload(); setUpdated(new Date()); } setPaused(!paused); }} aria-pressed={paused}>
            <Icon name={paused ? 'play' : 'pause'} />{paused ? `Resume${pending ? ` (${pending} new)` : ''}` : 'Pause updates'}
          </button>
        } />
      <div className="sr-only" aria-live="polite">{lastEvent && !paused ? `New detection: ${lastEvent.decision} ${lastEvent.title}` : ''}</div>
      <div className="mb-3 flex flex-wrap gap-1.5" role="tablist" aria-label="Filter by decision">
        {FILTERS.map((f) => (
          <button key={f} role="tab" aria-selected={filter === f} onClick={() => setFilter(f)}
            className={`h-8 rounded-[3px] border px-3 font-mono text-[11px] tracking-wider transition-colors duration-150 ${filter === f ? 'border-primary bg-primary text-on-primary' : 'border-line bg-surface text-muted hover:border-line-strong hover:text-ink'}`}>{f}</button>
        ))}
      </div>
      {error ? <ErrorBox error={error} /> : !data ? <Loading /> : <section className="card"><DetectionTable rows={rows} /></section>}
      {data && data.length >= 100 && <p className="mt-3 text-[12px] text-faint">Showing the latest 100. Use filters to narrow down.</p>}
    </>
  );
}
