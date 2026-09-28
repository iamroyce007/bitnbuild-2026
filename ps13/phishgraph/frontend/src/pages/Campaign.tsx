import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import DetectionTable from '../components/DetectionTable';
import GraphView, { GraphLegend, NodePanel } from '../components/GraphView';
import { DemoTag, ErrorBox, Loading, Section, Stat, riskColor } from '../components/ui';
import { api } from '../lib/api';
import type { GraphNode } from '../lib/types';
import { useApi } from '../lib/useApi';

export default function Campaign() {
  const { id = '' } = useParams();
  const { data, error } = useApi(() => api.campaign(id), [id]);
  const [node, setNode] = useState<GraphNode | null>(null);
  if (error) return <ErrorBox error={error} />;
  if (!data) return <Loading />;
  const s = data.stats;
  return (
    <>
      <div className="mb-1 text-[13px] text-muted"><Link to="/campaigns" className="hover:text-ink">Campaigns</Link> / <span className="font-mono">{data.id}</span></div>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <h1 className="text-[20px] font-semibold tracking-tight">{data.name}</h1>
        {data.demo && <DemoTag />}
        <span className="ml-auto font-mono text-[12px] text-faint">first seen {new Date(data.first_seen).toLocaleString()} · last {new Date(data.last_seen).toLocaleString()}</span>
      </div>
      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
        <Stat label="Risk" value={Math.round(data.risk)} color={riskColor(data.risk)} />
        <Stat label="Messages" value={s.emails ?? 0} />
        <Stat label="Domains" value={s.domains ?? 0} />
        <Stat label="IPs" value={s.ips ?? 0} />
        <Stat label="ASNs" value={s.asns ?? 0} />
        <Stat label="Certificates" value={s.certificates ?? 0} />
        <Stat label="Targets" value={<span className="text-[15px]">{data.brands.join(', ') || '—'}</span>} />
      </div>
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
        <Section title="Campaign infrastructure">
          <GraphView data={data.graph} height={520} onSelect={setNode} selectedId={node?.id} />
          <div className="mt-3"><GraphLegend /></div>
        </Section>
        <Section title="Selected node"><NodePanel node={node} /></Section>
      </div>
      <Section title={`Messages in this campaign (${data.detections.length})`} className="mt-5" flush><DetectionTable rows={data.detections} compact /></Section>
    </>
  );
}
