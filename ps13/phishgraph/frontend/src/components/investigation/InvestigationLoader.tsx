import { Check } from 'lucide-react';

// The real stages of the backend investigation chain (services/investigation.py -> pipeline.analyze(deep=True)).
export const STAGES = [
  'Normalising and SSRF check', 'Resolving DNS', 'Registration (RDAP)', 'TLS certificate', 'IP → network (ASN)',
  'Threat intelligence', 'Brand look-alikes', 'Mapping relationships', 'Campaign correlation', 'Risk fusion',
];

/** Staged progress with a small network constructing itself: one node per completed stage. */
export default function InvestigationLoader({ step, target }: { step: number; target: string }) {
  const done = Math.min(step, STAGES.length);
  const pts = STAGES.map((_, i) => {
    const a = (i / STAGES.length) * Math.PI * 2 - Math.PI / 2;
    return [60 + Math.cos(a) * (i % 2 ? 40 : 30), 60 + Math.sin(a) * (i % 2 ? 40 : 30)];
  });
  return (
    <div className="card scanlines relative overflow-hidden p-6" role="status" aria-live="polite">
      <div className="grid items-center gap-6 md:grid-cols-[180px_1fr]">
        <svg viewBox="0 0 120 120" className="mx-auto size-40" aria-hidden="true">
          {pts.slice(0, done).map(([x, y], i) => (
            <line key={`l${i}`} x1="60" y1="60" x2={x} y2={y} stroke="var(--color-accent)" strokeOpacity="0.5" strokeWidth="1" className="edge-in" style={{ ['--len' as string]: '50' }} />
          ))}
          {pts.slice(1, done).map(([x, y], i) => (
            <line key={`r${i}`} x1={pts[i][0]} y1={pts[i][1]} x2={x} y2={y} stroke="var(--color-line-strong)" strokeWidth="1" className="edge-in" style={{ ['--len' as string]: '40' }} />
          ))}
          <circle cx="60" cy="60" r="7" fill="var(--color-surface)" stroke="var(--color-accent)" strokeWidth="2" />
          <circle cx="60" cy="60" r="7" fill="none" stroke="var(--color-accent)" className="node-pulse" />
          {pts.slice(0, done).map(([x, y], i) => <circle key={`n${i}`} cx={x} cy={y} r="3.2" fill="var(--color-ink)" className="node-in" />)}
          {done < STAGES.length && <circle cx={pts[done][0]} cy={pts[done][1]} r="3.2" fill="none" stroke="var(--color-accent)" className="blink" />}
        </svg>
        <div>
          <div className="font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-accent">Analysing infrastructure</div>
          <div className="mt-1 truncate font-mono text-[13px] text-ink">{target}</div>
          <ol className="mt-4 grid gap-x-6 gap-y-1.5 sm:grid-cols-2">
            {STAGES.map((s, i) => {
              const state = i < done ? 'done' : i === done ? 'active' : 'todo';
              return (
                <li key={s} className={`flex items-center gap-2.5 text-[12.5px] ${state === 'todo' ? 'text-faint' : 'text-ink'}`}>
                  <span className="grid size-4 place-items-center" aria-hidden="true">
                    {state === 'done' ? <Check className="size-3.5 text-allow" strokeWidth={3} /> : state === 'active' ? <span className="status-dot text-accent" /> : <span className="size-1.5 rounded-full border border-faint" />}
                  </span>
                  {s}<span className="sr-only">{state === 'done' ? ' (done)' : state === 'active' ? ' (in progress)' : ''}</span>
                </li>
              );
            })}
          </ol>
        </div>
      </div>
    </div>
  );
}
