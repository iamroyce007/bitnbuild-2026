import { Histogram } from '../components/charts';
import { ErrorBox, Loading, PageTitle, Section, Stat } from '../components/ui';
import { api } from '../lib/api';
import { useApi } from '../lib/useApi';

const SPLIT_LABEL: Record<string, string> = {
  random_stratified: 'Random stratified split',
  domain_grouped: 'Domain-grouped (no domain in both train and test)',
  cross_source_ealvaradob_to_phiusiil: 'Cross-dataset: ealvaradob → PhiUSIIL',
  cross_source_phiusiil_to_ealvaradob: 'Cross-dataset: PhiUSIIL → ealvaradob',
  cross_channel_email_to_sms: 'Cross-channel: email → SMS',
  cross_channel_sms_to_email: 'Cross-channel: SMS → email',
};
const pct = (v: number | undefined) => (v == null ? '—' : v.toFixed(3));

export default function Models() {
  const { data, error } = useApi(() => api.models());
  if (error) return <ErrorBox error={error} />;
  if (!data) return <Loading />;
  const d = data.drift;
  const active = data.registry.filter((m) => m.status === 'active');
  return (
    <>
      <PageTitle title="Model health" sub="Every number here comes from the training report on disk. Random splits overstate accuracy; the harder splits are shown alongside them." />
      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Score drift (PSI, 24 h)" value={d.score_psi_24h ?? '—'} sub={d.drift_level || 'not enough traffic yet'} />
        <Stat label="Flag-or-higher share, 24 h" value={d.phishing_ratio_24h != null ? `${Math.round(d.phishing_ratio_24h * 100)}%` : '—'} sub={`${d.recent_detections} detections`} />
        <Stat label="False-positive rate (reviewed)" value={d.false_positive_rate_reviewed != null ? `${Math.round(d.false_positive_rate_reviewed * 100)}%` : '—'} sub={`${d.reviewed} reviewed`} />
        <Stat label="Retraining queue" value={(data.training_queue.hard_negatives || 0) + (data.training_queue.confirmed_phishing || 0)} sub={`${data.training_queue.hard_negatives || 0} hard negatives`} />
      </div>
      {d.recommendation && <div className="mb-5 rounded-md border border-flag/40 px-4 py-2 text-[13px] text-flag">{d.recommendation}</div>}
      <div className="space-y-5">
        {active.map((m) => (
          <Section key={m.name} title={`${m.name === 'url' ? 'URL model' : 'Email / SMS NLP model'} · v${m.version}`} right={<span className="font-mono text-[12px] text-faint">trained {m.trained_at} · {m.data.n?.toLocaleString()} samples · sha {m.sha256_16}</span>} flush>
            <div className="overflow-x-auto">
              <table className="tbl">
                <thead><tr><th>Evaluation</th><th>Model</th><th className="text-right">Precision</th><th className="text-right">Recall</th><th className="text-right">F1</th><th className="text-right">ROC-AUC</th><th className="text-right">PR-AUC</th><th className="text-right">n</th></tr></thead>
                <tbody>
                  {Object.entries(m.splits).flatMap(([split, models]) => Object.entries(models).map(([name, r], i) => (
                    <tr key={split + name}>
                      <td className="text-[13px]">{i === 0 ? SPLIT_LABEL[split] || split : ''}</td>
                      <td className="font-mono text-[12px] text-muted">{name}</td>
                      {(['precision', 'recall', 'f1', 'roc_auc', 'pr_auc'] as const).map((k) => <td key={k} className={`text-right font-mono ${k === 'f1' && r.f1 < 0.75 ? 'text-quarantine' : ''}`}>{pct(r[k])}</td>)}
                      <td className="text-right font-mono text-[12px] text-faint">{r.n?.toLocaleString()}</td>
                    </tr>
                  )))}
                </tbody>
              </table>
            </div>
            {!!m.notes?.length && <div className="border-t border-line p-4 text-[13px] text-muted">{m.notes.map((n, i) => <p key={i}>{n}</p>)}</div>}
          </Section>
        ))}
        <div className="grid gap-5 md:grid-cols-2">
          <Section title="Confidence distribution (24 h)"><Histogram bins={d.confidence_histogram_24h || []} /></Section>
          <Section title="New patterns (24 h)">
            <dl className="space-y-2 text-[13px]">
              <div><dt className="label">New TLDs</dt><dd className="mt-1 font-mono">{d.new_tlds_24h?.join(', ') || 'none'}</dd></div>
              <div><dt className="label">Newly impersonated brands</dt><dd className="mt-1">{d.new_impersonated_brands_24h?.join(', ') || 'none'}</dd></div>
            </dl>
          </Section>
        </div>
      </div>
    </>
  );
}
