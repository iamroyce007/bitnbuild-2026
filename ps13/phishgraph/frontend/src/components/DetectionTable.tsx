import { useNavigate } from 'react-router-dom';
import type { DetectionSummary } from '../lib/types';
import { ago, DecisionPill, DemoTag, Empty, riskColor } from './ui';

export default function DetectionTable({ rows, compact = false }: { rows: DetectionSummary[]; compact?: boolean }) {
  const nav = useNavigate();
  if (!rows.length) return <Empty>No detections yet. Analyse a message or run the demo seed.</Empty>;
  return (
    <div className="overflow-x-auto">
      <table className="tbl">
        <thead>
          <tr>
            <th className="w-16">Risk</th>
            <th className="w-32">Decision</th>
            <th>Message</th>
            {!compact && <th className="w-40">Campaign</th>}
            <th className="w-24 text-right">When</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((d) => (
            <tr key={d.detection_id} className={`clickable ${Date.now() - new Date(d.created_at).getTime() < 20_000 ? 'row-new' : ''}`} onClick={() => nav(`/detections/${d.detection_id}`)}>
              <td className="font-mono font-medium" style={{ color: riskColor(d.risk_score) }}>{Math.round(d.risk_score)}</td>
              <td><DecisionPill decision={d.decision} /></td>
              <td className="max-w-0">
                <a href={`/detections/${d.detection_id}`} onClick={(e) => { e.preventDefault(); nav(`/detections/${d.detection_id}`); }} className="block truncate text-ink hover:underline">
                  {d.title || '(no subject)'}
                </a>
                <div className="mt-0.5 flex items-center gap-2 truncate text-[12px] text-muted">
                  <span className="font-mono text-faint">{d.channel || d.kind}</span>
                  {d.demo && <DemoTag />}
                  {d.status !== 'open' && <span className="font-mono text-faint">{d.status.replace('_', ' ')}</span>}
                  {!compact && d.top_reason && <span className="truncate">{d.top_reason}</span>}
                </div>
              </td>
              {!compact && <td className="font-mono text-[12px] text-muted">{d.campaign_id || '—'}</td>}
              <td className="text-right font-mono text-[12px] text-faint">{ago(d.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
