import { useNavigate } from 'react-router-dom';
import { DemoTag, Empty, ErrorBox, Loading, PageTitle, ago, riskColor } from '../components/ui';
import { api } from '../lib/api';
import { useApi } from '../lib/useApi';

export default function Campaigns() {
  const { data, error } = useApi(() => api.campaigns());
  const nav = useNavigate();
  return (
    <>
      <PageTitle title="Campaigns" sub="Messages grouped by semantic similarity, shared infrastructure, brand target and timing." />
      {error ? <ErrorBox error={error} /> : !data ? <Loading /> : !data.length ? <Empty>No campaigns yet.</Empty> : (
        <section className="card overflow-x-auto">
          <table className="tbl">
            <thead><tr><th>Campaign</th><th>Targets</th><th className="text-right">Messages</th><th className="text-right">Domains</th><th className="text-right">IPs</th><th className="text-right">Certs</th><th className="text-right">Risk</th><th className="text-right">Last seen</th></tr></thead>
            <tbody>
              {data.map((c) => (
                <tr key={c.id} className="clickable" onClick={() => nav(`/campaigns/${c.id}`)}>
                  <td>
                    <a href={`/campaigns/${c.id}`} onClick={(e) => { e.preventDefault(); nav(`/campaigns/${c.id}`); }} className="font-mono text-[12px] text-accent hover:underline">{c.id}</a>
                    <div className="flex items-center gap-2 text-[13px]">{c.name} {c.demo && <DemoTag />}</div>
                  </td>
                  <td className="text-[13px] text-muted">{c.brands.join(', ') || '—'}</td>
                  {(['emails', 'domains', 'ips', 'certificates'] as const).map((k) => <td key={k} className="text-right font-mono">{c.stats[k] ?? 0}</td>)}
                  <td className="text-right font-mono"><span className=" inline-flex items-center gap-2"><span className="h-3 w-[3px] rounded-full" style={{ background: riskColor(c.risk) }} aria-hidden="true" />{Math.round(c.risk)}</span></td>
                  <td className="text-right font-mono text-[12px] text-faint">{ago(c.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </>
  );
}
