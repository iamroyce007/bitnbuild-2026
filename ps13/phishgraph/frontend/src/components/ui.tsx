import type { ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import type { Decision, Reason } from '../lib/types';

export const DECISION_COLOR: Record<string, string> = { ALLOW: 'var(--color-allow)', FLAG: 'var(--color-flag)', QUARANTINE: 'var(--color-quarantine)', BLOCK: 'var(--color-block)' };
const DECISION_SHAPE: Record<string, string> = { ALLOW: '○', FLAG: '△', QUARANTINE: '◇', BLOCK: '■' }; // never colour alone

/** A translucent version of a theme colour (works with CSS variables, unlike hex+alpha). */
export const tint = (c: string, pct: number) => `color-mix(in srgb, ${c} ${pct}%, transparent)`;

export function riskColor(v: number | null | undefined) {
  if (v == null) return 'var(--color-faint)';
  return v >= 85 ? DECISION_COLOR.BLOCK : v >= 60 ? DECISION_COLOR.QUARANTINE : v >= 30 ? DECISION_COLOR.FLAG : DECISION_COLOR.ALLOW;
}

export function DecisionPill({ decision, large = false }: { decision: Decision | string; large?: boolean }) {
  const c = DECISION_COLOR[decision] || 'var(--color-muted)';
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-sm border font-semibold tracking-wide ${large ? 'px-2.5 py-1 text-[13px]' : 'px-1.5 py-px text-[11px]'}`}
      style={{ color: c, borderColor: tint(c, 35), background: tint(c, 8) }}>
      <span aria-hidden="true">{DECISION_SHAPE[decision] || '·'}</span>
      {decision}
    </span>
  );
}

export function ScoreRow({ label, value, note }: { label: string; value: number | null | undefined; note?: string }) {
  return (
    <div className="grid grid-cols-[140px_1fr_52px] items-center gap-3 py-1.5">
      <span className="text-[13px] text-muted">{label}</span>
      <div className="h-1.5 overflow-hidden rounded-full bg-surface-2" role="meter" aria-label={label} aria-valuenow={value ?? undefined} aria-valuemin={0} aria-valuemax={100}>
        {value != null && <div className="h-full rounded-full" style={{ width: `${Math.max(2, value)}%`, background: riskColor(value) }} />}
      </div>
      <span className={`text-right font-mono text-[13px] ${value == null ? 'text-faint' : ''}`} title={note}>{value == null ? 'n/a' : value.toFixed(0)}</span>
    </div>
  );
}

export function RiskNumber({ value, decision }: { value: number; decision: Decision }) {
  return (
    <div className="flex items-end gap-3">
      <span className="text-[44px] font-semibold leading-none" style={{ color: DECISION_COLOR[decision] }}>{Math.round(value)}</span>
      <div className="pb-1">
        <div className="label">Risk score / 100</div>
        <DecisionPill decision={decision} large />
      </div>
    </div>
  );
}

export function Stat({ label, value, sub, color }: { label: string; value: ReactNode; sub?: ReactNode; color?: string }) {
  return (
    <div className="card border-l-[3px] px-4 py-3" style={{ borderLeftColor: color || 'var(--color-line-strong)' }}>
      <div className="label">{label}</div>
      <div className="mt-1 text-[24px] font-semibold leading-tight" style={{ color }}>{value}</div>
      {sub && <div className="mt-0.5 text-[12px] text-faint">{sub}</div>}
    </div>
  );
}

export function Section({ title, right, children, className = '', flush = false }: { title: ReactNode; right?: ReactNode; children: ReactNode; className?: string; flush?: boolean }) {
  return (
    <section className={`card ${className}`}>
      <header className="flex min-h-10 items-center justify-between gap-3 border-b border-line px-4 py-1.5">
        <h2 className="text-[14px] font-semibold">{title}</h2>
        {right}
      </header>
      <div className={flush ? '' : 'p-4'}>{children}</div>
    </section>
  );
}

/** Where each page sits in the console; drives the breadcrumb and the sidebar groups (see App.tsx). */
export const NAV_GROUPS: { group: string; items: [string, string, string][] }[] = [
  { group: 'Monitor', items: [['/', 'overview', 'Overview'], ['/feed', 'feed', 'Live detections'], ['/review', 'review', 'Review queue']] },
  { group: 'Investigate', items: [['/analyze', 'analyze', 'Analyze message'], ['/investigate', 'investigate', 'Investigate URL'], ['/graph', 'graph', 'Threat graph'], ['/campaigns', 'campaigns', 'Campaigns']] },
  { group: 'Intelligence', items: [['/intel', 'intel', 'Threat intelligence'], ['/models', 'models', 'Model health']] },
  { group: 'Administration', items: [['/health', 'health', 'System health'], ['/setup', 'setup', 'Setup'], ['/settings', 'settings', 'Settings']] },
];

function Crumbs({ title }: { title: string }) {
  const { pathname } = useLocation();
  const root = '/' + pathname.split('/')[1];
  let group = '', parent: [string, string] | null = null;
  for (const g of NAV_GROUPS) for (const [to, , label] of g.items) {
    if (to === root) { group = g.group; if (pathname !== to && label !== title) parent = [to, label]; }
  }
  if (!group) return null;
  return (
    <nav aria-label="Breadcrumb" className="mb-1 text-[12px] text-faint">
      <ol className="flex flex-wrap items-center gap-1.5">
        <li>{group}</li>
        {parent && <><li aria-hidden="true">/</li><li><Link to={parent[0]} className="hover:text-accent hover:underline">{parent[1]}</Link></li></>}
        <li aria-hidden="true">/</li>
        <li aria-current="page" className="text-muted">{title}</li>
      </ol>
    </nav>
  );
}

export function PageTitle({ title, sub, right }: { title: string; sub?: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3 border-b border-line pb-4">
      <div className="min-w-0">
        <Crumbs title={title} />
        <h1 className="text-[20px] font-semibold">{title}</h1>
        {sub && <p className="mt-1 text-[13px] text-muted">{sub}</p>}
      </div>
      {right}
    </div>
  );
}

export function ReasonList({ reasons, limit = 12 }: { reasons: Reason[]; limit?: number }) {
  if (!reasons.length) return <Empty>No risk evidence was recorded for this item.</Empty>;
  return (
    <ul className="divide-y divide-line">
      {reasons.slice(0, limit).map((r, i) => (
        <li key={i} className="grid grid-cols-[100px_1fr_44px] gap-3 py-2">
          <span className="pt-0.5 text-[12px] font-medium capitalize text-faint">{r.category.replace(/_/g, ' ')}</span>
          <span className="text-[13px] leading-snug">{r.text}</span>
          <span className="text-right font-mono text-[12px] text-faint" title={`engine: ${r.source}`}>{r.weight.toFixed(2)}</span>
        </li>
      ))}
    </ul>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="py-6 text-center text-[13px] text-muted">{children}</div>;
}

export function ErrorBox({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : String(error);
  const auth = /401|API key/i.test(msg);
  return (
    <div role="alert" className="rounded border border-block/40 border-l-[3px] bg-block/5 px-3 py-2 text-[13px] text-ink">
      <span className="font-semibold text-block">Error.</span> {auth ? 'This server is private and this browser has no access. Open the setup link from its administrator.' : msg}
    </div>
  );
}

export function Loading({ label = 'Loading' }: { label?: string }) {
  return <div className="py-8 text-center text-[13px] text-faint" role="status">{label}…</div>;
}

export function DemoTag() {
  return <span className="rounded-sm border border-flag/40 bg-flag/5 px-1.5 py-px text-[10px] font-semibold tracking-wide text-flag" title="Seeded demonstration data, not real intelligence">DEMO DATA</span>;
}

export function ago(iso?: string | null) {
  if (!iso) return '';
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return `${Math.max(0, Math.round(s))}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

const P: Record<string, string> = {
  overview: 'M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z',
  feed: 'M3 12h4l3-8 4 16 3-8h4',
  analyze: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM21 21l-5-5',
  investigate: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9s-1.3 6.3-3.8 9c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3z',
  graph: 'M6 4a2 2 0 1 0 0 4 2 2 0 0 0 0-4zM18 4a2 2 0 1 0 0 4 2 2 0 0 0 0-4zM12 16a2 2 0 1 0 0 4 2 2 0 0 0 0-4zM7 7.8l4 8.4M17 7.8l-4 8.4M8 6h8',
  campaigns: 'M4 7l8-4 8 4-8 4zM4 12l8 4 8-4M4 17l8 4 8-4',
  intel: 'M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3',
  models: 'M9 3v3M15 3v3M9 18v3M15 18v3M3 9h3M3 15h3M18 9h3M18 15h3M6 6h12v12H6zM10 10h4v4h-4z',
  review: 'M4 5h16v11H8l-4 4zM8 10h8',
  health: 'M3 12h4l2-5 4 10 2-5h6',
  settings: 'M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM19.4 13a7.9 7.9 0 0 0 0-2l2-1.6-2-3.4-2.4 1a8 8 0 0 0-1.7-1L15 3.4h-4l-.3 2.6a8 8 0 0 0-1.7 1l-2.4-1-2 3.4 2 1.6a7.9 7.9 0 0 0 0 2l-2 1.6 2 3.4 2.4-1a8 8 0 0 0 1.7 1l.3 2.6h4l.3-2.6a8 8 0 0 0 1.7-1l2.4 1 2-3.4z',
  pause: 'M8 5v14M16 5v14',
  setup: 'M9 11l3 3 8-8M20 12v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h9',
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM21 21l-5-5',
  sun: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
  moon: 'M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z',
  menu: 'M4 6h16M4 12h16M4 18h16',
  play: 'M7 5l12 7-12 7z',
};
export function Icon({ name, className = 'size-4' }: { name: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={P[name] || ''} />
    </svg>
  );
}
