import { ArrowRight, Clock, CornerDownLeft, Loader2, Search, X } from 'lucide-react';
import { forwardRef, useEffect, useState } from 'react';
import { Kbd } from '../kit';

const RECENT_KEY = 'pg.recent-investigations';
// real, useful examples: two look-alikes the engine catches, one known-bad demo host, and a genuine site
export const EXAMPLES = ['gitbuh.io', 'paypa1-billing.com/webscr', 'sbi-kyc-update.site/kyc', 'github.com'];

export function recentInvestigations(): string[] {
  try { return JSON.parse(localStorage.getItem(RECENT_KEY) || '[]'); } catch { return []; }
}
export function rememberInvestigation(q: string) {
  try { localStorage.setItem(RECENT_KEY, JSON.stringify([q, ...recentInvestigations().filter((x) => x !== q)].slice(0, 6))); } catch { /* private mode */ }
}

/** Accepts a domain, URL or IP. Returns an error message, or '' when valid. */
export function validateIndicator(v: string): string {
  const s = v.trim();
  if (!s) return '';
  if (/\s/.test(s)) return 'One indicator at a time: a domain, URL or IP address (no spaces).';
  const host = s.replace(/^[a-z]+:\/\//i, '').split(/[/?#]/)[0].replace(/:\d+$/, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return '';
  if (!/^[\p{L}\p{N}-]+(\.[\p{L}\p{N}-]+)+$/u.test(host)) return 'That does not look like a domain, URL or IP address.';
  return '';
}

type Props = { value: string; onChange: (v: string) => void; onSubmit: (v: string) => void; busy?: boolean; size?: 'lg' | 'md'; autoFocus?: boolean; showExamples?: boolean };

/** Command-centre investigation bar: validation, clear, Enter to run, recent + example queries. */
const InvestigationInput = forwardRef<HTMLInputElement, Props>(function InvestigationInput({ value, onChange, onSubmit, busy, size = 'md', autoFocus, showExamples = true }, ref) {
  const [touched, setTouched] = useState(false);
  const [recent, setRecent] = useState<string[]>([]);
  useEffect(() => setRecent(recentInvestigations()), [busy]);
  const err = touched ? validateIndicator(value) : '';
  const go = (v: string) => { const q = v.trim(); if (!q || validateIndicator(q)) { setTouched(true); return; } rememberInvestigation(q); onSubmit(q); };
  const lg = size === 'lg';
  return (
    <div className="w-full">
      <form role="search" onSubmit={(e) => { e.preventDefault(); go(value); }}
        className={`group relative flex items-center gap-3 rounded-lg border bg-surface/80 backdrop-blur transition-[border-color,box-shadow] duration-200
          ${err ? 'border-block/60' : 'border-line-strong focus-within:border-accent/70'} focus-within:shadow-[0_0_0_4px_color-mix(in_srgb,var(--color-accent)_14%,transparent),0_20px_50px_-24px_color-mix(in_srgb,var(--color-accent)_60%,transparent)]
          ${lg ? 'h-16 px-5' : 'h-12 px-4'}`}>
        <span className={`relative grid shrink-0 place-items-center ${lg ? 'size-6' : 'size-5'}`} aria-hidden="true">
          {busy ? <Loader2 className="size-full spin text-accent" /> : <Search className="size-full text-faint transition-colors group-focus-within:text-accent" />}
        </span>
        <label htmlFor="investigate-input" className="sr-only">Investigate a domain, URL or IP address</label>
        <input ref={ref} id="investigate-input" value={value} autoFocus={autoFocus} disabled={busy}
          onChange={(e) => onChange(e.target.value)} onBlur={() => setTouched(!!value)}
          onKeyDown={(e) => { if (e.key === 'Escape') { onChange(''); setTouched(false); } }}
          inputMode="url" autoCapitalize="none" autoCorrect="off" spellCheck={false} autoComplete="off"
          aria-invalid={!!err} aria-describedby={err ? 'investigate-err' : undefined}
          placeholder="Investigate a domain, URL or IP address"
          className={`min-w-0 flex-1 bg-transparent font-mono text-ink outline-none placeholder:font-sans placeholder:text-faint focus-visible:outline-none ${lg ? 'text-[17px]' : 'text-[14px]'}`} />
        {value && !busy && (
          <button type="button" onClick={() => { onChange(''); setTouched(false); }} className="grid size-7 place-items-center rounded text-faint hover:bg-surface-2 hover:text-ink" aria-label="Clear">
            <X className="size-4" />
          </button>
        )}
        <span className="hidden items-center gap-1 sm:flex" aria-hidden="true"><Kbd>/</Kbd></span>
        <button type="submit" disabled={busy || !value.trim()} aria-label="Start investigation"
          className={`btn btn-primary shrink-0 ${lg ? 'h-10 px-4' : 'h-8 px-3'}`}>
          <span className="max-sm:hidden">Investigate</span><ArrowRight className="size-4" />
        </button>
      </form>
      {err ? <p id="investigate-err" role="alert" className="mt-2 text-[12px] text-block">{err}</p> : showExamples && (
        <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-2 text-[12px]">
          {recent.length > 0 ? (
            <>
              <span className="inline-flex items-center gap-1 font-mono text-[10.5px] uppercase tracking-[0.14em] text-faint"><Clock className="size-3" />Recent</span>
              {recent.slice(0, 4).map((r) => <Chip key={r} label={r} onClick={() => { onChange(r); go(r); }} />)}
            </>
          ) : (
            <>
              <span className="inline-flex items-center gap-1 font-mono text-[10.5px] uppercase tracking-[0.14em] text-faint"><CornerDownLeft className="size-3" />Try</span>
              {EXAMPLES.map((r) => <Chip key={r} label={r} onClick={() => { onChange(r); go(r); }} />)}
            </>
          )}
        </div>
      )}
    </div>
  );
});
export default InvestigationInput;

function Chip({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button type="button" onClick={onClick} className="rounded-[4px] border border-line bg-surface-2/60 px-2 py-1 font-mono text-[11.5px] text-muted transition-colors hover:border-accent/50 hover:text-ink">
      {label}
    </button>
  );
}
