import { useState } from 'react';
import { Link } from 'react-router-dom';
import { DecisionPill, DemoTag, Empty, ErrorBox, Loading, PageTitle, ago, riskColor } from '../components/ui';
import { api } from '../lib/api';
import { useApi } from '../lib/useApi';

export default function Review() {
  const { data, error, reload } = useApi(() => api.detections('?limit=100&status=open&min_risk=30'));
  const [msg, setMsg] = useState('');
  const act = async (id: string, label: 'confirmed_phishing' | 'false_positive') => {
    const r = await api.feedback(id, label);
    setMsg(label === 'confirmed_phishing' ? `Confirmed. ${r.iocs_added} indicator(s) added to the local feed.` : 'Marked as false positive and queued as a hard negative.');
    reload();
  };
  return (
    <>
      <PageTitle title="Review queue" sub="Open detections at FLAG or above. Confirmations feed the local threat feed and graph; false positives become retraining data." />
      {msg && <p className="mb-3 text-[13px] text-muted" role="status">{msg}</p>}
      {error ? <ErrorBox error={error} /> : !data ? <Loading /> : !data.length ? <Empty>Nothing waiting for review.</Empty> : (
        <section className="card overflow-x-auto">
          <table className="tbl">
            <thead><tr><th className="w-14">Risk</th><th className="w-32">Decision</th><th>Message</th><th className="w-20 text-right">When</th><th className="w-64 text-right">Verdict</th></tr></thead>
            <tbody>
              {data.map((d) => (
                <tr key={d.detection_id}>
                  <td className="font-mono"><span className=" inline-flex items-center gap-2"><span className="h-3 w-[3px] rounded-full" style={{ background: riskColor(d.risk_score) }} aria-hidden="true" />{Math.round(d.risk_score)}</span></td>
                  <td><DecisionPill decision={d.decision} /></td>
                  <td className="max-w-0">
                    <Link to={`/detections/${d.detection_id}`} className="block truncate hover:underline">{d.title}</Link>
                    <div className="flex items-center gap-2 truncate text-[12px] text-muted">{d.demo && <DemoTag />}{d.top_reason}</div>
                  </td>
                  <td className="text-right font-mono text-[12px] text-faint">{ago(d.created_at)}</td>
                  <td className="text-right">
                    <div className="inline-flex gap-1.5">
                      <button className="btn h-8 text-[12px]" onClick={() => act(d.detection_id, 'confirmed_phishing')}>Confirm</button>
                      <button className="btn h-8 text-[12px]" onClick={() => act(d.detection_id, 'false_positive')}>False positive</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </>
  );
}
