import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import GraphView, { GraphLegend, NodePanel } from '../components/GraphView';
import ReportView from '../components/ReportView';
import { ErrorBox, Loading, Section } from '../components/ui';
import { api } from '../lib/api';
import type { GraphNode } from '../lib/types';
import { useApi } from '../lib/useApi';

export default function Detection() {
  const { id = '' } = useParams();
  const det = useApi(() => api.detection(id), [id]);
  const graph = useApi(() => api.graphDetection(id), [id]);
  const [node, setNode] = useState<GraphNode | null>(null);
  if (det.error) return <ErrorBox error={det.error} />;
  if (!det.data) return <Loading />;
  const d = det.data;
  return (
    <>
      <div className="mb-4 flex flex-wrap items-center gap-2 text-[13px] text-muted">
        <Link to="/feed" className="hover:text-ink">Detections</Link><span>/</span><span className="font-mono">{id.slice(0, 8)}</span>
        <span className="ml-auto font-mono text-[12px] text-faint">{new Date(d.created_at).toLocaleString()} · models {Object.entries(d.model_versions).map(([k, v]) => `${k} ${v}`).join(', ')}</span>
      </div>
      <ReportView r={d.report} status={d.status} />
      <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Section title="Relationship graph">
          {graph.data ? <GraphView data={graph.data} height={440} onSelect={setNode} selectedId={node?.id} /> : <Loading />}
          <div className="mt-3"><GraphLegend /></div>
        </Section>
        <div className="space-y-5">
          <Section title="Selected node"><NodePanel node={node} /></Section>
          <Section title="Response & review history">
            <ul className="space-y-2 text-[13px]">
              {d.actions.map((a, i) => <li key={`a${i}`}><span className="font-mono text-[12px] text-faint">{new Date(a.at).toLocaleTimeString()}</span> {a.action} <span className="text-faint">({a.mode})</span> — {a.result}</li>)}
              {d.feedback.map((f, i) => <li key={`f${i}`}><span className="font-mono text-[12px] text-faint">{new Date(f.at).toLocaleTimeString()}</span> analyst {f.analyst}: {f.label.replace('_', ' ')}{f.note && ` — ${f.note}`}</li>)}
              {!d.actions.length && !d.feedback.length && <li className="text-muted">No actions yet.</li>}
            </ul>
          </Section>
        </div>
      </div>
    </>
  );
}
