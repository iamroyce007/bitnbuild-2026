// Threat graph without a graph library: deterministic Fruchterman-Reingold layout computed once per data set,
// rendered as SVG. Each entity type has its own Lucide icon; known-bad nodes pulse; packets travel along edges that
// touch threats or the selection; nodes and edges reveal outward from the focus (breadth-first "discovery");
// hover shows metadata, click focuses, double-click expands real relationships (onExpand), full-screen on demand.
// Skill guidance (ui-ux-pro-max chart "Network Graph"): SVG up to a few hundred nodes, type encoded by icon + label,
// never colour alone, the relationships table is the accessible source of truth.
import { Award, Building2, Crosshair, FileWarning, Globe, Layers, Link2, type LucideIcon, Mail, Maximize2, Minimize2, Minus, Network, Paperclip, Plus, Rss, Scan, Server, Shield, User } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { GraphData, GraphNode } from '../lib/types';
import { CopyButton, SeverityBadge, sevOfScore } from './kit';
import { ago } from './ui';

export const TYPE_LABEL: Record<string, string> = {
  email: 'Email', url: 'URL', domain: 'Domain', ip: 'IP address', asn: 'Network (ASN)', cert: 'Certificate', ns: 'Nameserver', brand: 'Brand',
  campaign: 'Campaign', sender: 'Sender', attachment: 'Attachment', feed: 'Threat feed', platform: 'Hosting platform',
};
type Icon = LucideIcon;
export const TYPE_ICON: Record<string, Icon> = {
  email: Mail, url: Link2, domain: Globe, ip: Server, asn: Network, cert: Award, ns: Layers, brand: Building2,
  campaign: Crosshair, sender: User, attachment: Paperclip, feed: Rss, platform: Scan,
};
const iconOf = (t: string): Icon => TYPE_ICON[t] || Shield;

function nodeColor(n: GraphNode) {
  if (n.malicious) return 'var(--color-block)';
  const r = n.risk ?? 0;
  if (r >= 85) return 'var(--color-block)';
  if (r >= 60) return 'var(--color-quarantine)';
  if (r >= 30) return 'var(--color-flag)';
  if (n.type === 'brand' || n.official || n.tranco_rank) return 'var(--color-accent)';
  if (n.type === 'campaign') return 'var(--color-campaign)';
  return 'var(--color-neutral)';
}
const reduced = () => typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

/** Fruchterman-Reingold on one connected component inside a w x h box. */
function frComponent(n: number, edges: [number, number][], w: number, h: number) {
  const k = Math.sqrt((w * h) / Math.max(1, n)) * 0.75;
  const x = new Float64Array(n), y = new Float64Array(n), dx = new Float64Array(n), dy = new Float64Array(n);
  for (let i = 0; i < n; i++) { // deterministic golden-angle start: same graph, same picture
    const a = i * 2.399963, rad = Math.sqrt(i + 0.5) * k * 0.5;
    x[i] = w / 2 + Math.cos(a) * rad;
    y[i] = h / 2 + Math.sin(a) * rad;
  }
  let t = w / 6;
  const iters = n > 120 ? 160 : 240;
  for (let it = 0; it < iters && n > 1; it++) {
    dx.fill(0); dy.fill(0);
    for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) {
      let ddx = x[i] - x[j], ddy = y[i] - y[j];
      const d2 = ddx * ddx + ddy * ddy || 0.01;
      const f = (k * k) / d2;
      ddx *= f; ddy *= f;
      dx[i] += ddx; dy[i] += ddy; dx[j] -= ddx; dy[j] -= ddy;
    }
    for (const [a, b] of edges) {
      const ddx = x[a] - x[b], ddy = y[a] - y[b];
      const f = (Math.sqrt(ddx * ddx + ddy * ddy) || 0.01) / k;
      dx[a] -= ddx * f; dy[a] -= ddy * f; dx[b] += ddx * f; dy[b] += ddy * f;
    }
    for (let i = 0; i < n; i++) {
      dx[i] += (w / 2 - x[i]) * 0.05; dy[i] += (h / 2 - y[i]) * 0.05;
      const d = Math.sqrt(dx[i] * dx[i] + dy[i] * dy[i]) || 1;
      x[i] += (dx[i] / d) * Math.min(d, t);
      y[i] += (dy[i] / d) * Math.min(d, t);
    }
    t *= 0.97;
  }
  return { x, y };
}

/** Lay out each connected component separately, then shelf-pack them (largest first) so clusters sit side by side. */
function layout(data: GraphData) {
  const nodes = data.nodes.slice(0, 260);
  const idx = new Map(nodes.map((n, i) => [n.id, i]));
  const edges = data.edges.map((e) => [idx.get(e.source), idx.get(e.target)] as const).filter(([a, b]) => a != null && b != null && a !== b) as [number, number][];
  const parent = nodes.map((_, i) => i);
  const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  for (const [a, b] of edges) parent[find(a)] = find(b);
  const groups = new Map<number, number[]>();
  nodes.forEach((_, i) => { const r = find(i); if (!groups.has(r)) groups.set(r, []); groups.get(r)!.push(i); });
  const comps = [...groups.values()].sort((a, b) => b.length - a.length);
  const pos: [number, number][] = nodes.map(() => [0, 0]);
  const GAP = 40;
  const rowWidth = Math.max(700, Math.sqrt(nodes.length) * 150);
  let cx = 0, cy = 0, rowH = 0;
  for (const c of comps) {
    const local = new Map(c.map((g, i) => [g, i]));
    const ce = edges.filter(([a, b]) => local.has(a) && local.has(b)).map(([a, b]) => [local.get(a)!, local.get(b)!] as [number, number]);
    const side = 60 + 58 * Math.sqrt(c.length);
    const { x, y } = frComponent(c.length, ce, side * 1.3, side);
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    c.forEach((_, i) => { minX = Math.min(minX, x[i]); minY = Math.min(minY, y[i]); maxX = Math.max(maxX, x[i]); maxY = Math.max(maxY, y[i]); });
    const cw = maxX - minX + 60, ch = maxY - minY + 50;
    if (cx > 0 && cx + cw > rowWidth) { cx = 0; cy += rowH + GAP; rowH = 0; }
    c.forEach((g, i) => { pos[g] = [cx + 30 + x[i] - minX, cy + 20 + y[i] - minY]; });
    cx += cw + GAP;
    rowH = Math.max(rowH, ch);
  }
  let maxX = 0, maxY = 0;
  for (const [x, y] of pos) { maxX = Math.max(maxX, x); maxY = Math.max(maxY, y); }
  return { nodes, pos, edges, box: [-20, -20, maxX + 60, maxY + 60] as [number, number, number, number], relOf: data.edges };
}

export default function GraphView({ data, height = 480, onSelect, selectedId, onExpand }: {
  data: GraphData; height?: number; onSelect?: (n: GraphNode | null) => void; selectedId?: string | null; onExpand?: (n: GraphNode) => void;
}) {
  const L = useMemo(() => layout(data), [data]);
  const [view, setView] = useState<[number, number, number, number] | null>(null);
  const [hover, setHover] = useState<number | null>(null);
  const [tip, setTip] = useState<{ x: number; y: number } | null>(null);
  const [full, setFull] = useState(false);
  const drag = useRef<{ x: number; y: number; v: [number, number, number, number] } | null>(null);
  const svg = useRef<SVGSVGElement>(null);
  const wrap = useRef<HTMLDivElement>(null);
  const vb = view || L.box;
  useEffect(() => setView(null), [data]);
  useEffect(() => {
    const onFs = () => setFull(document.fullscreenElement === wrap.current);
    document.addEventListener('fullscreenchange', onFs);
    return () => document.removeEventListener('fullscreenchange', onFs);
  }, []);
  const neighbours = useMemo(() => {
    const m = new Map<number, Set<number>>();
    for (const [a, b] of L.edges) { if (!m.has(a)) m.set(a, new Set()); if (!m.has(b)) m.set(b, new Set()); m.get(a)!.add(b); m.get(b)!.add(a); }
    return m;
  }, [L]);
  // breadth-first distance from the focus nodes (or the riskiest node): drives the outward "discovery" reveal
  const dist = useMemo(() => {
    const d = new Array(L.nodes.length).fill(-1);
    let seeds = L.nodes.map((n, i) => (n.focus ? i : -1)).filter((i) => i >= 0);
    if (!seeds.length && L.nodes.length) seeds = [L.nodes.reduce((best, n, i) => ((n.risk ?? 0) > (L.nodes[best].risk ?? 0) ? i : best), 0)];
    const q = [...seeds];
    seeds.forEach((i) => (d[i] = 0));
    while (q.length) { const x = q.shift()!; for (const y of neighbours.get(x) || []) if (d[y] < 0) { d[y] = d[x] + 1; q.push(y); } }
    return d.map((v) => (v < 0 ? 4 : Math.min(v, 6)));
  }, [L, neighbours]);
  const sel = selectedId ? L.nodes.findIndex((n) => n.id === selectedId) : -1;
  const hot = hover ?? (sel >= 0 ? sel : null);
  const motion = !reduced();
  // packets only on edges that matter (touching a threat or the selection), capped for performance
  const packetEdges = useMemo(() => L.edges.map((e, i) => [e, i] as const)
    .filter(([[a, b]]) => L.nodes[a].malicious || L.nodes[b].malicious || a === sel || b === sel).slice(0, 36), [L, sel]);

  const zoom = (f: number) => {
    const [x, y, w, h] = vb;
    setView([x + (w * (1 - f)) / 2, y + (h * (1 - f)) / 2, w * f, h * f]);
  };
  const toggleFull = async () => {
    try { if (document.fullscreenElement) await document.exitFullscreen(); else await wrap.current?.requestFullscreen(); } catch { setFull((f) => !f); }
  };
  if (!L.nodes.length) return (
    <div className="grid place-items-center rounded-md border border-dashed border-line-strong text-center" style={{ height }}>
      <div className="max-w-xs px-6">
        <Network className="mx-auto mb-3 size-8 text-faint" strokeWidth={1.5} />
        <div className="text-[14px] font-semibold">No relationships mapped yet</div>
        <p className="mt-1 text-[12px] text-muted">Investigate a domain or analyse a message; its infrastructure appears here as it is discovered.</p>
      </div>
    </div>
  );
  const hn = hover != null ? L.nodes[hover] : null;

  return (
    <div ref={wrap} className={`relative overflow-hidden rounded-md border border-line bg-bg/60 ${full ? 'fixed inset-0 z-50 rounded-none border-0 bg-bg' : ''}`}>
      <div className="scanlines pointer-events-none absolute inset-0 opacity-40" aria-hidden="true" />
      <svg ref={svg} viewBox={vb.join(' ')} className="relative w-full cursor-grab touch-none select-none active:cursor-grabbing" style={{ height: full ? '100vh' : height }}
        role="group" aria-label={`Threat graph with ${L.nodes.length} entities and ${L.edges.length} relationships`}
        onWheel={(e) => zoom(e.deltaY > 0 ? 1.12 : 0.89)}
        onPointerDown={(e) => { if ((e.target as Element).tagName === 'svg') { drag.current = { x: e.clientX, y: e.clientY, v: vb }; (e.target as Element).setPointerCapture(e.pointerId); onSelect?.(null); } }}
        onPointerMove={(e) => {
          if (hover != null && wrap.current) { const r = wrap.current.getBoundingClientRect(); setTip({ x: e.clientX - r.left, y: e.clientY - r.top }); }
          if (!drag.current || !svg.current) return;
          const s = drag.current.v[2] / svg.current.clientWidth;
          setView([drag.current.v[0] - (e.clientX - drag.current.x) * s, drag.current.v[1] - (e.clientY - drag.current.y) * s, drag.current.v[2], drag.current.v[3]]);
        }}
        onPointerUp={() => { drag.current = null; }}>
        <defs>
          <radialGradient id="gv-halo"><stop offset="0" stopColor="var(--color-accent)" stopOpacity="0.35" /><stop offset="1" stopColor="var(--color-accent)" stopOpacity="0" /></radialGradient>
        </defs>
        <g>
          {L.edges.map(([a, b], i) => {
            const on = hot != null && (a === hot || b === hot);
            const bad = L.nodes[a].malicious && L.nodes[b].malicious;
            const [x1, y1] = L.pos[a], [x2, y2] = L.pos[b];
            const len = Math.hypot(x2 - x1, y2 - y1);
            return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} className={motion ? 'edge-in' : ''}
              style={{ ['--len' as string]: `${len}`, animationDelay: `${Math.max(dist[a], dist[b]) * 90}ms` }}
              stroke={on ? 'var(--color-accent)' : bad ? 'color-mix(in srgb, var(--color-block) 45%, transparent)' : 'var(--color-line-strong)'}
              strokeOpacity={hot != null && !on ? 0.35 : 0.9} strokeWidth={on ? 1.6 : 1} />;
          })}
          {motion && packetEdges.map(([[a, b], i]) => (
            <circle key={`p${i}`} r="1.8" fill={L.nodes[a].malicious || L.nodes[b].malicious ? 'var(--color-block)' : 'var(--color-accent)'} opacity="0.9">
              <animateMotion dur={`${2.2 + (i % 5) * 0.45}s`} begin={`${(i % 7) * 0.3}s`} repeatCount="indefinite" path={`M${L.pos[a][0]},${L.pos[a][1]} L${L.pos[b][0]},${L.pos[b][1]}`} />
            </circle>
          ))}
          {hot != null && L.relOf.filter((e) => e.source === L.nodes[hot].id || e.target === L.nodes[hot].id).slice(0, 14).map((e, i) => {
            const a = L.nodes.findIndex((n) => n.id === e.source), b = L.nodes.findIndex((n) => n.id === e.target);
            if (a < 0 || b < 0) return null;
            return <text key={`r${i}`} x={(L.pos[a][0] + L.pos[b][0]) / 2} y={(L.pos[a][1] + L.pos[b][1]) / 2} fontSize="8" fill="var(--color-muted)" textAnchor="middle" paintOrder="stroke" stroke="var(--color-bg)" strokeWidth="3" fontFamily="var(--font-mono)" letterSpacing="0.06em">{e.rel}</text>;
          })}
          {L.nodes.map((n, i) => {
            const dim = hot != null && i !== hot && !neighbours.get(hot)?.has(i);
            const focus = n.focus || i === sel;
            const show = focus || n.malicious || i === hot || (hot != null && neighbours.get(hot)?.has(i)) || ['campaign', 'brand', 'platform'].includes(n.type);
            const c = nodeColor(n);
            const r = focus ? 13 : 10;
            const Ico = iconOf(n.type);
            return (
              <g key={n.id} transform={`translate(${L.pos[i][0]},${L.pos[i][1]})`} opacity={dim ? 0.22 : 1} tabIndex={0} role="button"
                className="cursor-pointer outline-none [&:focus-visible>circle.ring]:stroke-[var(--color-accent)]"
                aria-label={`${TYPE_LABEL[n.type] || n.type} ${n.label}${n.malicious ? ', known malicious' : ''}. Press Enter to select, E to expand.`}
                onPointerEnter={() => setHover(i)} onPointerLeave={() => { setHover(null); setTip(null); }} onFocus={() => setHover(i)} onBlur={() => setHover(null)}
                onClick={() => onSelect?.(n)} onDoubleClick={() => onExpand?.(n)}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') onSelect?.(n); if (e.key.toLowerCase() === 'e') onExpand?.(n); }}>
                <g className={motion ? 'node-in' : ''} style={{ animationDelay: `${dist[i] * 90}ms` }}>
                  {n.malicious && motion && i < 400 && <circle r={r} fill="none" stroke="var(--color-block)" strokeWidth="1.2" className="node-pulse" style={{ animationDelay: `${(i % 9) * 0.25}s` }} />}
                  {focus && <circle r={r * 2.4} fill="url(#gv-halo)" />}
                  <circle className="ring" r={r} fill="var(--color-surface)" stroke={c} strokeWidth={focus ? 2 : 1.4} />
                  <Ico x={-r * 0.55} y={-r * 0.55} size={r * 1.1} strokeWidth={2} color={c} />
                </g>
                {show && <text y={r + 11} fontSize={focus ? 10.5 : 8.5} fill={focus ? 'var(--color-ink)' : 'var(--color-muted)'} textAnchor="middle" paintOrder="stroke" stroke="var(--color-bg)" strokeWidth="3" fontFamily="var(--font-mono)">
                  {String(n.label).length > 34 ? String(n.label).slice(0, 32) + '…' : n.label}
                </text>}
              </g>
            );
          })}
        </g>
      </svg>
      {hn && tip && (
        <div className="pop pointer-events-none absolute z-10 max-w-[280px] rounded-md border border-line-strong bg-surface/95 px-3 py-2 text-[12px] shadow-xl backdrop-blur"
          style={{ left: Math.min(tip.x + 14, (wrap.current?.clientWidth || 400) - 290), top: tip.y + 14 }}>
          <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.14em] text-faint">{TYPE_LABEL[hn.type] || hn.type}{hn.malicious && <span className="text-block">· known bad</span>}</div>
          <div className="mt-0.5 break-all font-mono text-ink">{hn.label}</div>
          <div className="mt-1 flex flex-wrap gap-x-3 text-faint">
            {hn.risk != null && <span>risk {Math.round(hn.risk)}</span>}
            {typeof hn.feed === 'string' && <span>feed {hn.feed}</span>}
            {hn.last_seen && <span>seen {ago(hn.last_seen)}</span>}
            <span>{neighbours.get(hover!)?.size || 0} links</span>
          </div>
          {onExpand && <div className="mt-1 text-[10.5px] text-faint">double-click to expand</div>}
        </div>
      )}
      <div className="absolute right-2 top-2 flex gap-1">
        <button className="btn h-8 px-2.5 text-[12px]" onClick={() => setView(null)}>Fit</button>
        <button className="btn h-8 w-8 px-0" onClick={() => zoom(0.8)} aria-label="Zoom in"><Plus className="size-3.5" /></button>
        <button className="btn h-8 w-8 px-0" onClick={() => zoom(1.25)} aria-label="Zoom out"><Minus className="size-3.5" /></button>
        <button className="btn h-8 w-8 px-0" onClick={toggleFull} aria-label={full ? 'Exit full screen' : 'Full screen'}>{full ? <Minimize2 className="size-3.5" /> : <Maximize2 className="size-3.5" />}</button>
      </div>
    </div>
  );
}

export function GraphLegend() {
  const kinds = ['domain', 'url', 'ip', 'ns', 'cert', 'email', 'brand', 'campaign', 'platform', 'feed'];
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[11.5px] text-muted">
      {kinds.map((k) => { const I = iconOf(k); return <span key={k} className="inline-flex items-center gap-1.5"><I size={13} strokeWidth={2} className="text-faint" />{TYPE_LABEL[k]}</span>; })}
      <span className="inline-flex items-center gap-1.5"><span className="size-2.5 rounded-full border-2 border-block" />known bad</span>
      <span className="inline-flex items-center gap-1.5"><span className="size-2.5 rounded-full border-2 border-accent" />brand / official</span>
    </div>
  );
}

const FIELD_LABEL: Record<string, string> = {
  risk: 'Risk', registrable: 'Registrable domain', registrar: 'Registrar', age_days: 'Domain age (days)', tranco_rank: 'Tranco rank',
  asn: 'ASN', country: 'Country', channel: 'Channel', feed: 'Listed in', first_seen: 'First seen', last_seen: 'Last seen', issuer: 'Issuer',
};

/** Node details: identity, threat level, key attributes, and its relationships (clickable), from real graph data. */
export function NodePanel({ node, data, onSelect }: { node: GraphNode | null; data?: GraphData | null; onSelect?: (n: GraphNode) => void }) {
  if (!node) return (
    <div className="py-4 text-center">
      <Crosshair className="mx-auto mb-2 size-6 text-faint" strokeWidth={1.5} />
      <p className="text-[13px] text-muted">Select an entity in the graph to inspect it.</p>
      <p className="mt-1 text-[11.5px] text-faint">Double-click (or press E) to expand its relationships.</p>
    </div>
  );
  const Ico = iconOf(node.type);
  const value = String(node.id).split(':').slice(1).join(':') || node.label;
  const sev = node.malicious ? 'CRITICAL' : node.risk != null ? sevOfScore(node.risk) : null;
  const skip = new Set(['id', 'label', 'focus', 'type', 'malicious', 'demo', 'official']);
  const attrs = Object.entries(node).filter(([k, v]) => !skip.has(k) && v !== null && v !== undefined && v !== '' && typeof v !== 'object');
  const rels = data ? data.edges.filter((e) => e.source === node.id || e.target === node.id) : [];
  const byRel = rels.reduce<Record<string, GraphNode[]>>((acc, e) => {
    const other = data!.nodes.find((n) => n.id === (e.source === node.id ? e.target : e.source));
    if (other) (acc[e.rel] ||= []).push(other);
    return acc;
  }, {});
  return (
    <div className="drawer-in space-y-4 text-[13px]" key={node.id}>
      <div className="flex items-start gap-3">
        <span className="grid size-10 shrink-0 place-items-center rounded-md border border-line-strong bg-surface-2"><Ico size={18} strokeWidth={1.75} className="text-accent" /></span>
        <div className="min-w-0 flex-1">
          <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-faint">{TYPE_LABEL[node.type] || node.type}</div>
          <div className="mt-0.5 flex items-start gap-1"><span className="break-all font-mono text-[13px] text-ink">{value}</span><CopyButton value={value} /></div>
        </div>
      </div>
      {sev && (
        <div className="flex items-center justify-between rounded-md border border-line bg-surface-2/50 px-3 py-2">
          <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-faint">Threat level</span>
          <SeverityBadge severity={sev} size="md" />
        </div>
      )}
      {node.malicious && <p className="flex items-center gap-2 text-[12px] text-muted"><FileWarning className="size-3.5 text-block" />Listed as malicious by a threat feed or confirmed by an analyst.</p>}
      {attrs.length > 0 && (
        <dl className="grid grid-cols-[120px_1fr] gap-x-3 gap-y-1.5">
          {attrs.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-[12px] text-faint">{FIELD_LABEL[k] || k.replace(/_/g, ' ')}</dt>
              <dd className="break-all font-mono text-[12px]">{k.endsWith('_seen') && typeof v === 'string' ? `${ago(v)} · ${v.slice(0, 10)}` : typeof v === 'boolean' ? (v ? 'yes' : 'no') : typeof v === 'number' ? Math.round(v * 10) / 10 : String(v)}</dd>
            </div>
          ))}
        </dl>
      )}
      {Object.keys(byRel).length > 0 && (
        <div>
          <div className="mb-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-faint">Relationships ({rels.length})</div>
          <div className="space-y-2">
            {Object.entries(byRel).map(([rel, ns]) => (
              <div key={rel}>
                <div className="font-mono text-[10.5px] text-faint">{rel}</div>
                <ul className="mt-0.5 space-y-0.5">
                  {ns.slice(0, 6).map((o) => { const I = iconOf(o.type); return (
                    <li key={o.id}><button className="flex w-full items-center gap-2 rounded px-1.5 py-1 text-left text-[12px] hover:bg-surface-2" onClick={() => onSelect?.(o)}>
                      <I size={13} strokeWidth={2} className={o.malicious ? 'text-block' : 'text-faint'} /><span className="truncate font-mono">{o.label}</span></button></li>); })}
                  {ns.length > 6 && <li className="px-1.5 text-[11px] text-faint">+{ns.length - 6} more</li>}
                </ul>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
