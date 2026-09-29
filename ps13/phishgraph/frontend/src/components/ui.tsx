import { type ReactNode, useEffect, useRef, useState } from 'react';
import { Activity, BookOpen, Cpu, Database, FlaskConical, HeartPulse, House, Keyboard, LayoutDashboard, ListChecks, type LucideIcon, Menu, Moon, Network, Pause, Play, Puzzle, Radar, ScanText, Search, Settings, Sun, Target } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import type { Decision, Reason } from '../lib/types';

export const DECISION_COLOR: Record<string, string> = { ALLOW: 'var(--color-allow)', FLAG: 'var(--color-flag)', QUARANTINE: 'var(--color-quarantine)', BLOCK: 'var(--color-block)' };
const DECISION_SHAPE: Record<string, string> = { ALLOW: '○', FLAG: '△', QUARANTINE: '◇', BLOCK: '■' }; // never colour alone

const reduced = () => typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

/** Animate a number from its previous value to `to` (ease-out, ~700 ms). Renders the final value under reduced motion. */
export function useCountUp(to: number, ms = 700) {
  const [v, setV] = useState(reduced() ? to : 0);
  const from = useRef(0);
  useEffect(() => {
    if (reduced()) { setV(to); from.current = to; return; }
    const start = performance.now(), a = from.current;
    let raf = 0;
    const tick = (t: number) => {
      const k = Math.min(1, (t - start) / ms), e = 1 - Math.pow(1 - k, 3);
      setV(a + (to - a) * e);
      if (k < 1) raf = requestAnimationFrame(tick); else from.current = to;
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [to, ms]);
  return v;
}

export function CountUp({ value, decimals = 0 }: { value: number; decimals?: number }) {
  const v = useCountUp(value);
  return <>{v.toLocaleString(undefined, { minimumFractionDigits: decimals, maximumFractionDigits: decimals })}</>;
}

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
      style={{ color: 'var(--color-ink)', borderColor: tint(c, 45), background: tint(c, 10) }}>
      <span aria-hidden="true" style={{ color: c }}>{DECISION_SHAPE[decision] || '·'}</span>
      {decision}
    </span>
  );
}

export function ScoreRow({ label, value, note }: { label: string; value: number | null | undefined; note?: string }) {
  return (
    <div className="grid grid-cols-[140px_1fr_52px] items-center gap-3 py-1.5">
      <span className="text-[13px] text-muted">{label}</span>
      <div className="h-1.5 overflow-hidden rounded-full bg-surface-2" role="meter" aria-label={label} aria-valuenow={value ?? undefined} aria-valuemin={0} aria-valuemax={100}>
        {value != null && <div className="bar-grow h-full rounded-full" style={{ width: `${Math.max(2, value)}%`, background: riskColor(value) }} />}
      </div>
      <span className={`text-right font-mono text-[13px] ${value == null ? 'text-faint' : ''}`} title={note}>{value == null ? 'n/a' : value.toFixed(0)}</span>
    </div>
  );
}

/** Semicircular dial that sweeps to the risk score, with the three decision thresholds ticked on the arc. */
export function RiskNumber({ value, decision }: { value: number; decision: Decision }) {
  const v = useCountUp(value, 900);
  const R = 46, C = Math.PI * R;
  const at = (p: number) => { const a = Math.PI * (1 - p / 100); return [60 + R * Math.cos(a), 58 - R * Math.sin(a)]; };
  return (
    <div className="flex items-center gap-4">
      <svg viewBox="0 0 120 66" className="h-[76px] w-[138px] shrink-0" role="img" aria-label={`Risk ${Math.round(value)} of 100, ${decision}`}>
        <path d={`M14 58 A${R} ${R} 0 0 1 106 58`} fill="none" stroke="var(--color-surface-2)" strokeWidth="9" strokeLinecap="round" />
        <path d={`M14 58 A${R} ${R} 0 0 1 106 58`} fill="none" stroke={DECISION_COLOR[decision]} strokeWidth="9" strokeLinecap="round"
          strokeDasharray={C} strokeDashoffset={C * (1 - v / 100)} />
        {[30, 60, 85].map((t) => { const [x, y] = at(t); const [x2, y2] = [60 + (x - 60) * 0.78, 58 + (y - 58) * 0.78]; return <line key={t} x1={x} y1={y} x2={x2} y2={y2} stroke="var(--color-faint)" strokeWidth="1" />; })}
        <text x="60" y="56" textAnchor="middle" fontSize="28" fontWeight="600" fill="var(--color-ink)" fontFamily="var(--font-sans)">{Math.round(v)}</text>
      </svg>
      <div>
        <div className="eyebrow">Risk / 100</div>
        <div className="mt-1"><DecisionPill decision={decision} large /></div>
      </div>
    </div>
  );
}

export function Stat({ label, value, sub, color }: { label: string; value: ReactNode; sub?: ReactNode; color?: string }) {
  return (
    <div className="card card-hover sheen relative overflow-hidden px-4 py-3.5">
      <span className="absolute inset-x-0 top-0 h-[2px] origin-left bar-grow" style={{ background: color ? `linear-gradient(90deg, ${color}, transparent)` : 'linear-gradient(90deg, var(--color-accent), transparent)', boxShadow: `0 0 14px ${color || 'var(--color-accent)'}` }} aria-hidden="true" />
      <div className="eyebrow">{label}</div>
      <div className="kpi-num mt-2 text-[28px] font-semibold leading-none tracking-tight">{typeof value === 'number' ? <CountUp value={value} /> : value}</div>
      {sub && <div className="mt-1.5 text-[12px] text-faint">{sub}</div>}
    </div>
  );
}

export function Section({ title, right, children, className = '', flush = false }: { title: ReactNode; right?: ReactNode; children: ReactNode; className?: string; flush?: boolean }) {
  return (
    <section className={`card min-w-0 ${className}`}>
      <header className="flex min-h-10 items-center justify-between gap-3 border-b border-line px-4 py-1.5">
        <h2 className="sec-title text-[14px] font-semibold">{title}</h2>
        {right}
      </header>
      <div className={`min-w-0 overflow-x-auto ${flush ? '' : 'p-4'}`}>{children}</div>
    </section>
  );
}

/** Where each page sits in the console; drives the breadcrumb and the sidebar groups (see App.tsx). */
export const NAV_GROUPS: { group: string; items: [string, string, string][] }[] = [
  { group: 'Investigate', items: [['/investigate', 'investigate', 'New investigation'], ['/analyze', 'analyze', 'Analyze message']] },
  { group: 'Workspace', items: [['/overview', 'overview', 'Overview'], ['/feed', 'feed', 'Live detections'], ['/review', 'review', 'Review queue']] },
  { group: 'Intelligence', items: [['/graph', 'graph', 'Threat graph'], ['/campaigns', 'campaigns', 'Campaigns'], ['/intel', 'intel', 'Threat feeds & indicators'], ['/models', 'models', 'Model health'], ['/validation', 'check', 'Training & validation']] },
  { group: 'System', items: [['/system', 'health', 'System health'], ['/setup', 'setup', 'Browser extension'], ['/documentation', 'docs', 'Documentation'], ['/settings', 'settings', 'Settings']] },
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
    <nav aria-label="Breadcrumb" className="eyebrow mb-1.5">
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
        <h1 className="text-[22px] font-semibold tracking-tight">{title}</h1>
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
  return <div className="space-y-2.5 py-4" role="status" aria-label={label}>
      <span className="sr-only">{label}…</span>
      {[92, 76, 84, 58].map((w, i) => <div key={i} className="skeleton h-3" style={{ width: `${w}%` }} />)}
    </div>;
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

// One icon system (Lucide), addressed by stable names so pages never import icons ad hoc.
const ICONS: Record<string, LucideIcon> = {
  overview: LayoutDashboard, feed: Activity, analyze: ScanText, investigate: Radar, graph: Network, campaigns: Target, intel: Database,
  models: Cpu, review: ListChecks, health: HeartPulse, settings: Settings, pause: Pause, play: Play, setup: Puzzle, search: Search,
  sun: Sun, moon: Moon, menu: Menu, check: FlaskConical, docs: BookOpen, keyboard: Keyboard, home: House,
};
export function Icon({ name, className = 'size-4' }: { name: string; className?: string }) {
  const I = ICONS[name] || Radar;
  return <I className={className} strokeWidth={1.75} aria-hidden="true" />;
}
