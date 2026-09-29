import { Award, Globe, Radar, ShieldAlert, Sparkles } from 'lucide-react';
import type { Report } from '../../lib/types';

type Ev = { at: Date; label: string; detail?: string; icon: typeof Globe; tone: 'accent' | 'block' | 'faint' };

/** Chronology built only from real fields: RDAP registration date, TLS certificate age, feed listings and the
 *  analysis events the pipeline recorded. Nothing is invented; missing facts are simply absent. */
export function buildTimeline(r: Report): Ev[] {
  const at = new Date(r.analyzed_at || Date.now());
  const back = (days: number) => new Date(at.getTime() - days * 86400000);
  const ev: Ev[] = [];
  for (const u of r.urls.slice(0, 3)) {
    const e = (u.enrichment || {}) as Record<string, any>;
    if (e.rdap?.age_days != null) ev.push({ at: back(e.rdap.age_days), label: 'Domain registered', detail: `${u.registrable || u.host}${e.rdap.registrar ? ` · ${e.rdap.registrar}` : ''}`, icon: Globe, tone: 'faint' });
    if (e.tls?.age_days != null) ev.push({ at: back(e.tls.age_days), label: 'TLS certificate issued', detail: `${e.tls.issuer || 'issuer unknown'} · ${u.host}`, icon: Award, tone: 'faint' });
  }
  for (const s of r.threat_intel?.sources || []) {
    if (s.verdict === 'malicious' || s.verdict === 'suspicious') ev.push({ at, label: `Listed by ${s.display || s.source}`, detail: s.summary, icon: ShieldAlert, tone: 'block' });
  }
  for (const t of r.timeline || []) ev.push({ at: new Date(t.at), label: t.event, detail: t.source, icon: t.source?.startsWith('graph') ? Radar : Sparkles, tone: 'accent' });
  return ev.filter((e) => !Number.isNaN(e.at.getTime())).sort((a, b) => a.at.getTime() - b.at.getTime());
}

export default function ThreatTimeline({ report }: { report: Report }) {
  const ev = buildTimeline(report);
  if (!ev.length) return <p className="text-[12.5px] text-muted">No dated evidence yet. Registration and certificate dates appear after full enrichment.</p>;
  return (
    <ol className="discover relative space-y-4 pl-6">
      <span className="absolute bottom-1 left-[7px] top-1 w-px bg-gradient-to-b from-accent/60 via-line-strong to-transparent" aria-hidden="true" />
      {ev.map((e, i) => {
        const I = e.icon;
        const c = e.tone === 'block' ? 'var(--color-block)' : e.tone === 'accent' ? 'var(--color-accent)' : 'var(--color-faint)';
        return (
          <li key={i} className="relative">
            <span className="absolute -left-6 top-0.5 grid size-[15px] place-items-center rounded-full border bg-surface" style={{ borderColor: c }} aria-hidden="true">
              <I className="size-2.5" style={{ color: c }} strokeWidth={2.5} />
            </span>
            <div className="font-mono text-[10.5px] tracking-[0.08em] text-faint">{e.at.toISOString().slice(0, 10)} {e.at.toISOString().slice(11, 16)} UTC</div>
            <div className="text-[13px] text-ink">{e.label}</div>
            {e.detail && <div className="break-words text-[12px] text-muted">{e.detail}</div>}
          </li>
        );
      })}
    </ol>
  );
}
