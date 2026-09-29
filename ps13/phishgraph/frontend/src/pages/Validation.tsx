import { useMemo, useState } from 'react';
import { ErrorBox, Loading, PageTitle, Section, Stat } from '../components/ui';
import { api, type Metric, type TrainingRun, type ValidationRun } from '../lib/api';
import { useApi } from '../lib/useApi';

// Every number on this page comes from a run that actually happened: models/registry.json (training) and
// data/validation/history.json (written by scripts/run_tests.py, feature_check.py, eval_fresh_feed.py, eval_lookalike.py).

const KIND: Record<string, { label: string; color: string }> = {
  unit_tests: { label: 'Unit & property tests', color: 'var(--color-accent)' },
  feature_check: { label: 'End-to-end feature check', color: 'var(--color-allow)' },
  fresh_feed: { label: 'Live phishing feed (unseen)', color: 'var(--color-flag)' },
  lookalike: { label: 'Look-alike engine', color: 'var(--color-campaign)' },
  real_world: { label: 'Real-world URLs (feeds off)', color: 'var(--color-quarantine)' },
};
const SPLIT_LABEL: Record<string, string> = {
  random_stratified: 'Random split', domain_grouped: 'Domain-grouped (no shared domains)',
  cross_source_ealvaradob_to_phiusiil: 'Cross-dataset A → B', cross_source_phiusiil_to_ealvaradob: 'Cross-dataset B → A',
  cross_channel_email_to_sms: 'Cross-channel email → SMS', cross_channel_sms_to_email: 'Cross-channel SMS → email',
};
const pct = (v: unknown, d = 1) => (typeof v === 'number' ? `${(v * 100).toFixed(d)}%` : '–');
const when = (iso: string) => new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const deployed = (name: string) => (name === 'url' ? 'blend_mean' : 'blend');

function Delta({ now, before }: { now?: number; before?: number }) {
  if (now == null || before == null) return null;
  const d = now - before;
  if (Math.abs(d) < 0.0005) return <span className="ml-1 font-mono text-[11px] text-faint">±0</span>;
  return <span className="ml-1 font-mono text-[11px]" style={{ color: d > 0 ? 'var(--color-allow)' : 'var(--color-block)' }}>{d > 0 ? '▲' : '▼'}{(Math.abs(d) * 100).toFixed(1)}</span>;
}

/** Tiny SVG trend of a metric across runs (oldest → newest). */
function Spark({ values, color }: { values: number[]; color: string }) {
  if (values.length < 2) return null;
  const max = Math.max(...values), min = Math.min(...values), span = max - min || 1;
  const pts = values.map((v, i) => `${(i / (values.length - 1)) * 100},${28 - ((v - min) / span) * 24}`).join(' ');
  return (
    <svg viewBox="0 0 100 30" preserveAspectRatio="none" className="h-8 w-28" aria-hidden="true">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="2" vectorEffect="non-scaling-stroke" style={{ filter: `drop-shadow(0 0 4px ${color})` }} />
    </svg>
  );
}

function TrainingTable({ runs }: { runs: TrainingRun[] }) {
  const byModel = useMemo(() => {
    const m: Record<string, TrainingRun[]> = {};
    for (const r of [...runs].sort((a, b) => a.version - b.version)) (m[r.name] ||= []).push(r);
    return m;
  }, [runs]);
  return (
    <div className="space-y-6">
      {Object.entries(byModel).map(([name, versions]) => {
        const splits = Object.keys(versions[versions.length - 1].splits || {});
        return (
          <div key={name}>
            <div className="mb-2 flex flex-wrap items-baseline gap-2">
              <h3 className="text-[14px] font-semibold">{name === 'url' ? 'URL model' : 'Email / SMS language model'}</h3>
              <span className="text-[12px] text-faint">F1 of the deployed blend per evaluation split; change vs the previous version</span>
            </div>
            <table className="tbl">
              <thead><tr><th>Version</th><th>Trained</th><th>Data</th>{splits.map((s) => <th key={s} className="text-right">{SPLIT_LABEL[s] || s}</th>)}{name === 'url' && <th className="text-right">Live feed recall / false alarms</th>}</tr></thead>
              <tbody>
                {[...versions].reverse().map((v) => {
                  const prev = versions[versions.indexOf(v) - 1];
                  const ff = v.fresh_feed as Record<string, unknown> | null | undefined;
                  const data = v.data as { n?: number; by_source?: Record<string, number>; feedback?: { used?: number } } | null;
                  return (
                    <tr key={v.version}>
                      <td className="whitespace-nowrap"><span className="font-mono font-semibold">v{v.version}</span>{' '}
                        <span className={`ml-1 rounded-full px-2 py-px text-[10px] font-semibold uppercase tracking-wider ${v.status === 'active' ? 'bg-allow/15 text-allow' : 'bg-surface-2 text-faint'}`}>{v.status}</span></td>
                      <td className="whitespace-nowrap text-[12px] text-muted">{when(v.trained_at)}</td>
                      <td className="text-[12px] text-muted">{data?.n?.toLocaleString()}{data?.by_source?.tranco ? ' +Tranco' : ''}{data?.feedback?.used ? ` +${data.feedback.used} feedback` : ''}</td>
                      {splits.map((s) => {
                        const m = v.splits?.[s]?.[deployed(name)] as Metric | undefined;
                        const pm = prev?.splits?.[s]?.[deployed(name)] as Metric | undefined;
                        return <td key={s} className="whitespace-nowrap text-right font-mono">{m ? m.f1.toFixed(3) : '–'}<Delta now={m?.f1} before={pm?.f1} /></td>;
                      })}
                      {name === 'url' && <td className="whitespace-nowrap text-right font-mono">{ff?.status === 'ok' ? <>{pct(ff['recall_at_0.5'], 0)} / {pct(ff['fp_rate_at_0.5'], 0)}</> : '–'}</td>}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        );
      })}
    </div>
  );
}

function RunDetails({ run }: { run: ValidationRun }) {
  const [failedOnly, setFailedOnly] = useState(false);
  const d = run.details as Record<string, unknown>;
  if (run.kind === 'unit_tests') {
    const files = (d.by_file as { file: string; about: string; passed: number; failed: number }[]) || [];
    const failures = (d.failures as { test: string; message: string }[]) || [];
    return (
      <div className="space-y-3">
        <table className="tbl"><thead><tr><th>Test file</th><th>What it proves</th><th className="text-right">Passed</th><th className="text-right">Failed</th></tr></thead>
          <tbody>{files.map((f) => <tr key={f.file}><td className="font-mono text-[12px]">{f.file}</td><td className="text-[12px] text-muted">{f.about}</td><td className="text-right font-mono text-allow">{f.passed}</td><td className="text-right font-mono" style={{ color: f.failed ? 'var(--color-block)' : undefined }}>{f.failed}</td></tr>)}</tbody></table>
        {failures.map((f) => <div key={f.test} className="rounded-lg border border-block/40 bg-block/5 px-3 py-2 font-mono text-[12px]">{f.test}: {f.message}</div>)}
      </div>
    );
  }
  if (run.kind === 'feature_check' || run.kind === 'real_world') {
    const rows = ((d.rows as { area: string; check: string; ok: boolean; detail: string; ms: number | null }[]) || []).filter((r) => !failedOnly || !r.ok);
    return (
      <div className="space-y-2">
        <label className="flex items-center gap-2 text-[12px] text-muted"><input type="checkbox" className="accent-accent" checked={failedOnly} onChange={(e) => setFailedOnly(e.target.checked)} />Show failed checks only</label>
        <div className="max-h-[480px] overflow-auto rounded-lg border border-line">
          <table className="tbl"><thead><tr><th>Area</th><th>Check</th><th>Result</th><th>Detail</th><th className="text-right">ms</th></tr></thead>
            <tbody>{rows.map((r, i) => (
              <tr key={i}><td className="text-[12px] text-muted">{r.area}</td><td className="max-w-[320px] break-all font-mono text-[12px]">{r.check}</td>
                <td><span className="rounded-full px-2 py-px text-[10.5px] font-semibold" style={{ color: r.ok ? 'var(--color-allow)' : 'var(--color-block)', background: r.ok ? 'color-mix(in srgb, var(--color-allow) 14%, transparent)' : 'color-mix(in srgb, var(--color-block) 14%, transparent)' }}>{r.ok ? 'PASS' : 'FAIL'}</span></td>
                <td className="max-w-[420px] text-[12px] text-muted">{r.detail}</td><td className="text-right font-mono text-[12px] text-faint">{r.ms ?? ''}</td></tr>
            ))}</tbody></table>
        </div>
      </div>
    );
  }
  const flat = Object.entries(d).filter(([, v]) => typeof v !== 'object' || v === null);
  return (
    <dl className="grid gap-x-6 gap-y-1.5 text-[13px] sm:grid-cols-2">
      {flat.map(([k, v]) => <div key={k} className="flex justify-between gap-3 border-b border-line/60 py-1"><dt className="text-muted">{k.replace(/_/g, ' ')}</dt><dd className="text-right font-mono">{typeof v === 'number' && v <= 1 && !Number.isInteger(v) ? pct(v) : String(v)}</dd></div>)}
    </dl>
  );
}

function summaryText(r: ValidationRun) {
  const s = r.summary as Record<string, number>;
  if (r.kind === 'unit_tests') return `${s.passed}/${s.total} passed · ${s.seconds}s`;
  if (r.kind === 'feature_check') return `${s.passed}/${s.checks} checks · URLs ${s.urls_scored - ((s.false_positives as unknown as unknown[])?.length || 0) - ((s.false_negatives as unknown as unknown[])?.length || 0)}/${s.urls_scored} as expected`;
  if (r.kind === 'fresh_feed') return `recall ${pct(s['recall_at_0.5'])} on ${s.n_phishing} live phishing URLs · false alarms ${pct(s['fp_rate_at_0.5'])} on ${s.n_benign} real sites`;
  if (r.kind === 'real_world') return `${s.n_total} real URLs · live phishing flagged ${pct(s.phishing_flagged)} · long-tail false alarms ${pct(s.longtail_false_alarm)} · top sites ${pct(s.top_false_alarm)}`;
  if (r.kind === 'lookalike') return `${pct(s.curated_strong_recall)} of look-alike attacks caught · ${s.official_flagged} official domains flagged · ${pct(s.real_flag_rate, 2)} of real domains flagged`;
  return '';
}

function passed(r: ValidationRun) {
  const s = r.summary as Record<string, number>;
  if (r.kind === 'unit_tests') return s.failed === 0;
  if (r.kind === 'feature_check') return s.passed === s.checks;
  if (r.kind === 'real_world') return `${s.n_total} real URLs · live phishing flagged ${pct(s.phishing_flagged)} · long-tail false alarms ${pct(s.longtail_false_alarm)} · top sites ${pct(s.top_false_alarm)}`;
  if (r.kind === 'lookalike') return s.official_flagged === 0;
  return true;
}

export default function Validation() {
  const v = useApi(() => api.validation());
  const [open, setOpen] = useState<string | null>(null);
  const [kind, setKind] = useState('all');
  if (v.error) return <ErrorBox error={v.error} />;
  if (!v.data) return <Loading />;
  const { training, runs } = v.data;
  const latest = (k: string) => runs.find((r) => r.kind === k);
  const series = (k: string, f: (r: ValidationRun) => number) => runs.filter((r) => r.kind === k).map(f).reverse();
  const ut = latest('unit_tests'), fc = latest('feature_check'), ff = latest('fresh_feed'), la = latest('lookalike');
  const shown = runs.filter((r) => kind === 'all' || r.kind === kind);
  return (
    <>
      <PageTitle title="Training & validation" sub="Every model version and every test run, newest first. Nothing here is typed in by hand: each entry was written by the script that ran it." />
      <div className="stagger mb-5 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
        <Stat label="Unit & property tests" value={ut ? `${(ut.summary as { passed: number }).passed}` : '–'} sub={ut ? `of ${(ut.summary as { total: number }).total} · ${when(ut.at)}` : 'not run yet'} color={ut && passed(ut) ? 'var(--color-allow)' : undefined} />
        <Stat label="Feature check" value={fc ? `${(fc.summary as { passed: number }).passed}/${(fc.summary as { checks: number }).checks}` : '–'} sub={fc ? `${fc.target.replace(/^https?:\/\//, '')}` : 'not run yet'} />
        <Stat label="Live phishing caught" value={ff ? pct((ff.summary as Record<string, number>)['recall_at_0.5'], 0) : '–'} sub={ff ? `${(ff.summary as { n_phishing: number }).n_phishing} unseen OpenPhish URLs` : 'not run yet'} color="var(--color-flag)" />
        <Stat label="Official domains flagged" value={la ? String((la.summary as { official_flagged: number }).official_flagged) : '–'} sub="look-alike engine, must stay 0" color={la && passed(la) ? 'var(--color-allow)' : undefined} />
        <Stat label="Model versions" value={training.length} sub={`${training.filter((t) => t.status === 'active').length} active`} />
      </div>

      <Section title="Model training history" className="mb-5">
        <TrainingTable runs={training} />
      </Section>

      <Section title="Validation runs" right={
        <div className="flex flex-wrap gap-1">{['all', ...Object.keys(KIND)].map((k) => (
          <button key={k} onClick={() => setKind(k)} className={`h-7 rounded-full border px-2.5 text-[11px] ${kind === k ? 'border-accent/60 bg-accent/15 text-ink' : 'border-line text-muted hover:text-ink'}`}>{k === 'all' ? 'All' : KIND[k].label}</button>
        ))}</div>} flush>
        {!shown.length ? <p className="p-4 text-[13px] text-muted">No runs recorded yet. Run <code className="font-mono">python scripts/run_tests.py</code> or <code className="font-mono">scripts/feature_check.py</code>.</p> : (
          <>
            <div className="flex flex-wrap gap-6 border-b border-line px-4 py-3">
              {Object.entries(KIND).map(([k, { label, color }]) => {
                const vals = k === 'unit_tests' ? series(k, (r) => (r.summary as { passed: number }).passed)
                  : k === 'feature_check' ? series(k, (r) => (r.summary as { passed: number }).passed / Math.max(1, (r.summary as { checks: number }).checks))
                  : k === 'fresh_feed' ? series(k, (r) => (r.summary as Record<string, number>)['recall_at_0.5'])
                  : k === 'real_world' ? series(k, (r) => (r.summary as Record<string, number>).phishing_flagged)
                  : series(k, (r) => (r.summary as { curated_strong_recall: number }).curated_strong_recall);
                return vals.length ? <div key={k} className="flex items-center gap-2"><Spark values={vals} color={color} /><div><div className="eyebrow">{label}</div><div className="text-[12px] text-muted">{vals.length} run{vals.length > 1 ? 's' : ''}</div></div></div> : null;
              })}
            </div>
            <ul className="divide-y divide-line">
              {shown.map((r) => (
                <li key={r.id}>
                  <button className="flex w-full flex-wrap items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-surface-2/60" onClick={() => setOpen(open === r.id ? null : r.id)} aria-expanded={open === r.id}>
                    <span className="size-2.5 shrink-0 rounded-full" style={{ background: passed(r) ? KIND[r.kind]?.color || 'var(--color-accent)' : 'var(--color-block)', boxShadow: `0 0 10px ${KIND[r.kind]?.color || 'var(--color-accent)'}` }} />
                    <span className="min-w-[180px] text-[13px] font-semibold">{KIND[r.kind]?.label || r.kind}</span>
                    <span className="flex-1 text-[13px] text-muted">{summaryText(r)}</span>
                    <span className="font-mono text-[11px] text-faint">{r.target} · {when(r.at)}</span>
                    <span className="text-faint" aria-hidden="true">{open === r.id ? '−' : '+'}</span>
                  </button>
                  {open === r.id && <div className="pop border-t border-line bg-surface-2/30 px-4 py-4"><RunDetails run={r} /></div>}
                </li>
              ))}
            </ul>
          </>
        )}
      </Section>
    </>
  );
}
