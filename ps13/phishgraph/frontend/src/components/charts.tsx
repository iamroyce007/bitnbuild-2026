// Dependency-free SVG charts. Each has a text/table equivalent so nothing relies on colour or hover alone.
import { DECISION_COLOR } from './ui';

const ORDER = ['BLOCK', 'QUARANTINE', 'FLAG', 'ALLOW'] as const;

export function StackedBars({ data, height = 150 }: { data: ({ t: string } & Partial<Record<'ALLOW' | 'FLAG' | 'QUARANTINE' | 'BLOCK', number>>)[]; height?: number }) {
  if (!data.length) return <div className="py-10 text-center text-[13px] text-muted">No detections in this window yet.</div>;
  const max = Math.max(1, ...data.map((d) => ORDER.reduce((a, k) => a + (d[k] || 0), 0)));
  const w = 100 / data.length;
  return (
    <figure>
      <svg viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" className="h-[150px] w-full" role="img"
        aria-label={`Detections per hour, ${data.length} buckets, peak ${max}`}>
        {[0.25, 0.5, 0.75].map((f) => <line key={f} x1="0" x2="100" y1={height * f} y2={height * f} stroke="var(--color-line)" strokeWidth="0.5" vectorEffect="non-scaling-stroke" />)}
        {data.map((d, i) => {
          let y = height;
          return ORDER.slice().reverse().map((k) => {
            const h = ((d[k] || 0) / max) * (height - 6);
            y -= h;
            return h > 0 ? <rect key={`${i}${k}`} x={i * w + w * 0.18} width={w * 0.64} y={y} height={h} fill={DECISION_COLOR[k]} opacity={k === 'ALLOW' ? 0.55 : 0.9}><title>{`${d.t} ${k}: ${d[k]}`}</title></rect> : null;
          });
        })}
      </svg>
      <figcaption className="mt-2 flex flex-wrap justify-between gap-2 font-mono text-[11px] text-faint">
        <span>{data[0].t}</span>
        <span className="flex gap-3">{ORDER.map((k) => <span key={k} className="inline-flex items-center gap-1"><span className="size-2 rounded-sm" style={{ background: DECISION_COLOR[k] }} />{k}</span>)}</span>
        <span>{data[data.length - 1].t}</span>
      </figcaption>
    </figure>
  );
}

export function Histogram({ bins }: { bins: number[] }) {
  const max = Math.max(1, ...bins);
  return (
    <figure>
      <div className="flex h-24 items-end gap-1" role="img" aria-label={`Risk score distribution: ${bins.map((b, i) => `${i * 10}-${i * 10 + 9}: ${b}`).join(', ')}`}>
        {bins.map((b, i) => {
          const c = i >= 8.5 ? DECISION_COLOR.BLOCK : i >= 6 ? DECISION_COLOR.QUARANTINE : i >= 3 ? DECISION_COLOR.FLAG : DECISION_COLOR.ALLOW;
          return <div key={i} className="flex-1 rounded-sm" style={{ height: `${Math.max(b ? 4 : 1, (b / max) * 100)}%`, background: b ? c : 'var(--color-line)' }} title={`${i * 10}–${i * 10 + 9}: ${b}`} />;
        })}
      </div>
      <figcaption className="mt-1.5 flex justify-between font-mono text-[11px] text-faint"><span>0</span><span>50</span><span>100</span></figcaption>
    </figure>
  );
}

export function Meter({ parts }: { parts: { label: string; value: number; color: string }[] }) {
  const total = parts.reduce((a, p) => a + p.value, 0) || 1;
  return (
    <div>
      <div className="flex h-2 overflow-hidden rounded-full bg-surface-2">
        {parts.map((p) => <div key={p.label} style={{ width: `${(p.value / total) * 100}%`, background: p.color }} />)}
      </div>
      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-[13px]">
        {parts.map((p) => (
          <div key={p.label} className="flex items-center justify-between">
            <dt className="flex items-center gap-2 text-muted"><span className="size-2 rounded-sm" style={{ background: p.color }} />{p.label}</dt>
            <dd className="font-mono">{p.value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
