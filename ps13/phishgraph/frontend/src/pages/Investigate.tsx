import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import ReportView from '../components/ReportView';
import { ErrorBox, PageTitle, Section } from '../components/ui';
import { api } from '../lib/api';
import type { Report } from '../lib/types';

const STEPS = ['Normalise & SSRF check', 'DNS resolution', 'RDAP registration', 'TLS certificate', 'IP → ASN', 'Threat intelligence', 'Graph traversal', 'Brand similarity', 'Campaign similarity', 'Risk fusion'];

export default function Investigate() {
  const [params, setParams] = useSearchParams();
  const [url, setUrl] = useState(params.get('url') || '');
  const [job, setJob] = useState<string | null>(null);
  const [status, setStatus] = useState('');
  const [rep, setRep] = useState<Report | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [tick, setTick] = useState(0);
  const timer = useRef<number>();

  useEffect(() => () => window.clearTimeout(timer.current), []);
  const poll = async (id: string, n = 0) => {
    try {
      const j = await api.job(id);
      setStatus(j.status);
      setTick(n);
      if (j.status === 'done') {
        const r = j.result as unknown as Report & { error?: string };
        if (r?.error) setErr(new Error(r.error));
        else setRep(r);
        setJob(null);
        return;
      }
      if (j.status === 'failed') { setErr(new Error(j.error || 'investigation failed')); setJob(null); return; }
      timer.current = window.setTimeout(() => poll(id, n + 1), 700);
    } catch (e) {
      setErr(e);
      setJob(null);
    }
  };
  const run = async (target: string) => {
    setErr(null); setRep(null);
    try {
      const { job_id } = await api.investigate(target);
      setJob(job_id);
      poll(job_id);
    } catch (x) {
      setErr(x);
    }
  };
  const start = (e: React.FormEvent) => { e.preventDefault(); run(url.trim()); };
  // opened from the top-bar lookup: /investigate?url=...
  useEffect(() => {
    const u = params.get('url');
    if (u) { setUrl(u); run(u); setParams({}, { replace: true }); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params]);
  return (
    <>
      <PageTitle title="Investigate URL" sub="Runs the full chain on a link no feed has seen yet, and explains any link to known malicious infrastructure." />
      <Section title="Target" className="mb-5">
        <form onSubmit={start} className="flex flex-wrap gap-2">
          <label className="sr-only" htmlFor="u">URL to investigate</label>
          <input id="u" className="input flex-1 font-mono" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://suspicious-domain.example/login" />
          <button className="btn btn-primary" disabled={!url.trim() || !!job}>{job ? 'Investigating…' : 'Investigate'}</button>
        </form>
        <p className="mt-2 text-[12px] text-faint">Internal and private addresses (localhost, 10.x, 169.254.169.254 …) are refused. Nothing is fetched except DNS, RDAP and the TLS handshake.</p>
        {job && (
          <ol className="mt-4 grid gap-1.5 sm:grid-cols-2 lg:grid-cols-5" aria-live="polite">
            {STEPS.map((s, i) => (
              <li key={s} className={`rounded border px-2.5 py-1.5 font-mono text-[11px] ${i <= tick ? 'border-line-strong text-ink' : 'border-line text-faint'}`}>{s}</li>
            ))}
          </ol>
        )}
        {job && <p className="mt-2 font-mono text-[12px] text-muted">job {job.slice(0, 8)} · {status || 'queued'}</p>}
      </Section>
      {err ? <ErrorBox error={err} /> : rep && <ReportView r={rep} />}
    </>
  );
}
