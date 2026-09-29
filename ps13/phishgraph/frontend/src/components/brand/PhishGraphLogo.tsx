import { useId } from 'react';

/** PhishGraph mark: a shield drawn as graph edges (nodes on its vertices) with a hook descending from the top node;
 *  the hook's barb ends in the "threat" node. Network + protection + phishing, without clip-art. Used in the navbar,
 *  favicon (public/favicon.svg mirrors this geometry), loading screen and empty states. */
export function PhishGraphMark({ size = 28, animated = false, className = '' }: { size?: number; animated?: boolean; className?: string }) {
  const id = useId().replace(/:/g, '');
  return (
    <svg viewBox="0 0 32 32" width={size} height={size} className={className} role="img" aria-label="PhishGraph">
      <defs>
        <linearGradient id={`pg-${id}`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="var(--color-accent)" />
          <stop offset="1" stopColor="var(--color-accent-2)" />
        </linearGradient>
      </defs>
      {/* shield as a polygon of graph edges */}
      <path d="M16 2.8 27.2 7v8.4c0 6.6-4.6 11.6-11.2 13.8C9.4 27 4.8 22 4.8 15.4V7Z" fill="none" stroke={`url(#pg-${id})`}
        strokeWidth="1.6" strokeLinejoin="round" opacity="0.9" />
      {/* internal graph edges */}
      <path d="M16 9.2 22.4 12.6M16 9.2 9.6 12.6" stroke="var(--color-ink)" strokeOpacity="0.55" strokeWidth="1.2" strokeLinecap="round" />
      {/* the hook */}
      <path d="M16 9.2v9.6a3.7 3.7 0 0 1-7.4 0v-1.6" fill="none" stroke="var(--color-ink)" strokeWidth="1.9" strokeLinecap="round" />
      <path d="m8.6 17.2 2.1 1.7" stroke="var(--color-ink)" strokeWidth="1.6" strokeLinecap="round" />
      {/* nodes */}
      <circle cx="16" cy="2.8" r="1.7" fill={`url(#pg-${id})`} />
      <circle cx="27.2" cy="7" r="1.5" fill={`url(#pg-${id})`} />
      <circle cx="4.8" cy="7" r="1.5" fill={`url(#pg-${id})`} />
      <circle cx="16" cy="9.2" r="2.1" fill="var(--color-ink)" />
      <circle cx="22.4" cy="12.6" r="1.6" fill="var(--color-ink)" fillOpacity="0.8" />
      <circle cx="9.6" cy="12.6" r="1.6" fill="var(--color-ink)" fillOpacity="0.8" />
      <circle cx="8.6" cy="17.2" r="2" fill="var(--color-block)">
        {animated && <animate attributeName="r" values="2;2.6;2" dur="1.6s" repeatCount="indefinite" />}
      </circle>
    </svg>
  );
}

export function PhishGraphWordmark({ size = 24 }: { size?: number }) {
  return (
    <span className="inline-flex items-center gap-2.5">
      <PhishGraphMark size={size} />
      <span className="text-[15px] font-semibold tracking-[-0.02em]">Phish<span className="text-accent">Graph</span></span>
    </span>
  );
}

/** Full-screen brand loader (first paint / connecting). */
export function BrandLoader({ label = 'Connecting to the intelligence platform' }: { label?: string }) {
  return (
    <div className="grid min-h-full place-items-center" role="status">
      <div className="flex flex-col items-center gap-4">
        <PhishGraphMark size={56} animated />
        <div className="font-mono text-[11px] uppercase tracking-[0.2em] text-faint">{label}<span className="blink">…</span></div>
      </div>
    </div>
  );
}
