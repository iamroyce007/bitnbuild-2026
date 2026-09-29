// Shared premium UI kit: severity system, toasts, copy-to-clipboard, threat score, status badge, empty/error states.
import { AlertTriangle, Check, Copy, RotateCcw, X } from 'lucide-react';
import { type ReactNode, useEffect, useState } from 'react';
import type { Decision } from '../lib/types';
import { useCountUp } from './ui';

// ---- severity: one semantic scale for the whole product ------------------------------------------------------
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export const SEVERITY: Record<Decision, Severity> = { ALLOW: 'LOW', FLAG: 'MEDIUM', QUARANTINE: 'HIGH', BLOCK: 'CRITICAL' };
export const SEV_COLOR: Record<Severity, string> = { LOW: 'var(--color-allow)', MEDIUM: 'var(--color-flag)', HIGH: 'var(--color-quarantine)', CRITICAL: 'var(--color-block)' };
export const sevOfScore = (s: number): Severity => (s >= 85 ? 'CRITICAL' : s >= 60 ? 'HIGH' : s >= 30 ? 'MEDIUM' : 'LOW');

export function SeverityBadge({ severity, size = 'sm' }: { severity: Severity; size?: 'sm' | 'md' }) {
  const c = SEV_COLOR[severity];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-[4px] border font-mono font-semibold tracking-[0.12em] ${size === 'md' ? 'px-2 py-0.5 text-[11px]' : 'px-1.5 py-px text-[10px]'}`}
      style={{ color: 'var(--color-ink)', borderColor: `color-mix(in srgb, ${c} 40%, transparent)`, background: `color-mix(in srgb, ${c} 10%, transparent)` }}>
      <span className="size-1.5 rounded-full" style={{ background: c }} aria-hidden="true" />{severity}
    </span>
  );
}

export function StatusBadge({ label, tone = 'accent', live = false }: { label: string; tone?: 'accent' | 'allow' | 'flag' | 'block' | 'faint'; live?: boolean }) {
  const c = tone === 'faint' ? 'var(--color-faint)' : `var(--color-${tone})`;
  return (
    <span className="inline-flex items-center gap-2 font-mono text-[10.5px] font-medium uppercase tracking-[0.16em]" style={{ color: c }}>
      {live ? <span className="status-dot" /> : <span className="size-1.5 rounded-full" style={{ background: c }} />}{label}
    </span>
  );
}

// ---- toasts (tiny global bus; no provider needed) ------------------------------------------------------------
type Toast = { id: number; text: string; tone: 'ok' | 'error' | 'info' };
export function toast(text: string, tone: Toast['tone'] = 'ok') {
  window.dispatchEvent(new CustomEvent('pg:toast', { detail: { text, tone } }));
}
export function Toaster() {
  const [items, setItems] = useState<Toast[]>([]);
  useEffect(() => {
    let n = 0;
    const on = (e: Event) => {
      const t = { id: ++n, ...(e as CustomEvent).detail } as Toast;
      setItems((x) => [...x.slice(-3), t]);
      window.setTimeout(() => setItems((x) => x.filter((y) => y.id !== t.id)), 2600);
    };
    window.addEventListener('pg:toast', on);
    return () => window.removeEventListener('pg:toast', on);
  }, []);
  return (
    <div className="pointer-events-none fixed bottom-20 right-4 z-[60] flex flex-col items-end gap-2 lg:bottom-5" aria-live="polite">
      {items.map((t) => (
        <div key={t.id} className="toast-in card pointer-events-auto flex items-center gap-2.5 px-3.5 py-2.5 text-[13px]">
          {t.tone === 'error' ? <AlertTriangle className="size-4 text-block" /> : <Check className="size-4 text-allow" />}
          {t.text}
        </div>
      ))}
    </div>
  );
}

export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button type="button" aria-label={`${label}: ${value}`} title={label}
      className="inline-grid size-6 shrink-0 place-items-center rounded-[4px] text-faint transition-colors hover:bg-surface-2 hover:text-ink"
      onClick={async (e) => {
        e.stopPropagation();
        try { await navigator.clipboard.writeText(value); setDone(true); toast('Copied to clipboard'); window.setTimeout(() => setDone(false), 1200); }
        catch { toast('Clipboard not available', 'error'); }
      }}>
      {done ? <Check className="size-3.5 text-allow" /> : <Copy className="size-3.5" />}
    </button>
  );
}

// ---- threat score: radial gauge, animated number, contributing factors -------------------------------------
export function ThreatScore({ score, decision, factors = [] }: { score: number; decision: Decision; factors?: { label: string; value: number | null }[] }) {
  const v = useCountUp(score, 900);
  const sev = SEVERITY[decision];
  const c = SEV_COLOR[sev];
  const R = 52, C = 2 * Math.PI * R, arc = 0.75; // 270° gauge
  return (
    <div className="flex flex-col items-center">
      <div className="relative size-[150px]">
        <svg viewBox="0 0 128 128" className="size-full -rotate-[225deg]" aria-hidden="true">
          <defs>
            <linearGradient id="ts-grad" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0" stopColor="var(--color-allow)" /><stop offset="0.45" stopColor="var(--color-flag)" />
              <stop offset="0.75" stopColor="var(--color-quarantine)" /><stop offset="1" stopColor="var(--color-block)" />
            </linearGradient>
          </defs>
          <circle cx="64" cy="64" r={R} fill="none" stroke="var(--color-line)" strokeWidth="8" strokeDasharray={`${C * arc} ${C}`} strokeLinecap="round" />
          <circle cx="64" cy="64" r={R} fill="none" stroke="url(#ts-grad)" strokeWidth="8" strokeLinecap="round"
            strokeDasharray={`${C * arc * (v / 100)} ${C}`} style={{ filter: `drop-shadow(0 0 6px color-mix(in srgb, ${c} 55%, transparent))` }} />
        </svg>
        <div className="absolute inset-0 grid place-items-center" role="img" aria-label={`Threat score ${Math.round(score)} of 100, ${sev}`}>
          <div className="text-center">
            <div className="text-[44px] font-semibold leading-none tracking-[-0.04em] text-ink">{Math.round(v)}</div>
            <div className="mt-1 font-mono text-[10px] tracking-[0.2em] text-faint">/ 100</div>
          </div>
        </div>
      </div>
      <div className="-mt-3"><SeverityBadge severity={sev} size="md" /></div>
      {factors.length > 0 && (
        <ul className="discover mt-5 w-full space-y-2">
          {factors.map((f) => (
            <li key={f.label} className="grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1 text-[12px]">
              <span className="text-muted">{f.label}</span>
              <span className={`font-mono ${f.value == null ? 'text-faint' : 'text-ink'}`}>{f.value == null ? 'n/a' : Math.round(f.value)}</span>
              <span className="col-span-2 h-1 overflow-hidden rounded-full bg-surface-2">
                {f.value != null && <span className="bar-grow block h-full rounded-full" style={{ width: `${Math.max(3, f.value)}%`, background: SEV_COLOR[sevOfScore(f.value)] }} />}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ---- states ------------------------------------------------------------------------------------------------
export function ErrorState({ title = 'Investigation failed', detail, onRetry }: { title?: string; detail?: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="card border-block/30 p-6">
      <div className="flex items-start gap-3">
        <span className="grid size-9 shrink-0 place-items-center rounded-md bg-block/10 text-block"><X className="size-4" /></span>
        <div className="min-w-0">
          <div className="font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-block">{title}</div>
          {detail && <p className="mt-1 text-[13px] text-ink">{detail}</p>}
          <p className="mt-3 text-[12px] text-muted">Possible reasons:</p>
          <ul className="mt-1 list-disc space-y-0.5 pl-5 text-[12px] text-muted">
            <li>The indicator is not a valid public domain or URL (private addresses are refused on purpose)</li>
            <li>An external intelligence source is unavailable</li>
            <li>Rate limit reached: wait a few seconds</li>
            <li>Temporary network failure</li>
          </ul>
          {onRetry && <button className="btn mt-4" onClick={onRetry}><RotateCcw className="size-3.5" />Retry investigation</button>}
        </div>
      </div>
    </div>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="rounded-[4px] border border-line-strong bg-surface-2 px-1.5 py-px font-mono text-[10.5px] text-muted">{children}</kbd>;
}
