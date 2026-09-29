// Threat graph without a graph library: Fruchterman-Reingold layout computed once (no animation loop),
// rendered as SVG with pan/zoom, focusable nodes and shape + colour coding (never colour alone).
import { useMemo, useRef, useState } from 'react';
import type { GraphData, GraphNode } from '../lib/types';

export const TYPE_LABEL: Record<string, string> = {
  email: 'Email', url: 'URL', domain: 'Domain', ip: 'IP address', asn: 'ASN', cert: 'Certificate', ns: 'Nameserver', brand: 'Brand',
  campaign: 'Campaign', sender: 'Sender', attachment: 'Attachment', feed: 'Threat feed',
};

function nodeColor(n: GraphNode) {
  if (n.malicious) return 'var(--color-block)';
  const r = n.risk ?? 0;
  if (r >= 85) return 'var(--color-block)';
  if (r >= 60) return 'var(--color-quarantine)';
  if (r >= 30) return 'var(--color-flag)';
  if (n.type === 'brand') return 'var(--color-accent)';
  if (n.type === 'campaign') return 'var(--color-campaign)';
  return 'var(--color-neutral)';
}

function Shape({ type, r, fill, stroke }: { type: string; r: number; fill: string; stroke: string }) {
  const p = { fill, stroke, strokeWidth: 1.5 };
  switch (type) {
    case 'ip': return <rect x={-r} y={-r} width={2 * r} height={2 * r} transform="rotate(45)" {...p} />;
    case 'email': case 'attachment': return <rect x={-r * 1.2} y={-r * 0.85} width={r * 2.4} height={r * 1.7} rx={2} {...p} />;
    case 'ns': return <polygon points={`0,${-r * 1.2} ${r * 1.1},${r * 0.8} ${-r * 1.1},${r * 0.8}`} {...p} />;
    case 'cert': return <polygon points={`${-r},${-r * 0.7} ${r * 1.2},${-r * 0.7} ${r},${r * 0.7} ${-r * 1.2},${r * 0.7}`} {...p} />;
    case 'asn': case 'campaign': return <polygon points={Array.from({ length: 6 }, (_, i) => `${Math.cos((i * Math.PI) / 3) * r * 1.15},${Math.sin((i * Math.PI) / 3) * r * 1.15}`).join(' ')} {...p} />;
    case 'feed': return <rect x={-r} y={-r} width={2 * r} height={2 * r} {...p} />;
    default: return <circle r={r} {...p} />;
  }
}

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

export default function GraphView({ data, height = 480, onSelect, selectedId }: { data: GraphData; height?: number; onSelect?: (n: GraphNode | null) => void; selectedId?: string | null }) {
  const L = useMemo(() => layout(data), [data]);
  const [view, setView] = useState<[number, number, number, number] | null>(null);
  const [hover, setHover] = useState<number | null>(null);
  const drag = useRef<{ x: number; y: number; v: [number, number, number, number] } | null>(null);
  const svg = useRef<SVGSVGElement>(null);
  const vb = view || L.box;
  const neighbours = useMemo(() => {
    const m = new Map<number, Set<number>>();
    for (const [a, b] of L.edges) { if (!m.has(a)) m.set(a, new Set()); if (!m.has(b)) m.set(b, new Set()); m.get(a)!.add(b); m.get(b)!.add(a); }
    return m;
  }, [L]);
  const sel = selectedId ? L.nodes.findIndex((n) => n.id === selectedId) : -1;
  const hot = hover ?? (sel >= 0 ? sel : null);

  const zoom = (f: number) => {
    const [x, y, w, h] = vb;
    setView([x + (w * (1 - f)) / 2, y + (h * (1 - f)) / 2, w * f, h * f]);
  };
  if (!L.nodes.length) return <div className="grid place-items-center rounded-md bg-bg text-[13px] text-muted" style={{ height }}>No graph data yet.</div>;

  return (
    <div className="relative">
      <svg ref={svg} viewBox={vb.join(' ')} className="w-full cursor-grab touch-none select-none rounded-md bg-bg active:cursor-grabbing" style={{ height }}
        role="group" aria-label={`Threat graph with ${L.nodes.length} nodes and ${L.edges.length} relationships`}
        onWheel={(e) => zoom(e.deltaY > 0 ? 1.12 : 0.89)}
        onPointerDown={(e) => { if ((e.target as Element).tagName === 'svg') { drag.current = { x: e.clientX, y: e.clientY, v: vb }; (e.target as Element).setPointerCapture(e.pointerId); onSelect?.(null); } }}
        onPointerMove={(e) => {
          if (!drag.current || !svg.current) return;
          const s = drag.current.v[2] / svg.current.clientWidth;
          setView([drag.current.v[0] - (e.clientX - drag.current.x) * s, drag.current.v[1] - (e.clientY - drag.current.y) * s, drag.current.v[2], drag.current.v[3]]);
        }}
        onPointerUp={() => { drag.current = null; }}>
        <g>
          {L.edges.map(([a, b], i) => {
            const on = hot != null && (a === hot || b === hot);
            return <line key={i} x1={L.pos[a][0]} y1={L.pos[a][1]} x2={L.pos[b][0]} y2={L.pos[b][1]} stroke={on ? 'var(--color-accent)' : 'var(--color-line-strong)'} strokeWidth={on ? 1.6 : 1} />;
          })}
          {hot != null && L.relOf.filter((e) => e.source === L.nodes[hot].id || e.target === L.nodes[hot].id).slice(0, 14).map((e, i) => {
            const a = L.nodes.findIndex((n) => n.id === e.source), b = L.nodes.findIndex((n) => n.id === e.target);
            if (a < 0 || b < 0) return null;
            return <text key={`r${i}`} x={(L.pos[a][0] + L.pos[b][0]) / 2} y={(L.pos[a][1] + L.pos[b][1]) / 2} fontSize="9" fill="var(--color-muted)" textAnchor="middle" paintOrder="stroke" stroke="var(--color-surface)" strokeWidth="3" fontFamily="var(--font-mono)">{e.rel}</text>;
          })}
          {L.nodes.map((n, i) => {
            const dim = hot != null && i !== hot && !neighbours.get(hot)?.has(i);
            const focus = n.focus || i === sel;
            const show = focus || n.malicious || i === hot || (hot != null && neighbours.get(hot)?.has(i)) || ['campaign', 'brand'].includes(n.type);
            const c = nodeColor(n);
            return (
              <g key={n.id} transform={`translate(${L.pos[i][0]},${L.pos[i][1]})`} opacity={dim ? 0.25 : 1} tabIndex={0} role="button" className="cursor-pointer outline-none"
                aria-label={`${TYPE_LABEL[n.type] || n.type} ${n.label}${n.malicious ? ', known bad' : ''}`}
                onPointerEnter={() => setHover(i)} onPointerLeave={() => setHover(null)} onFocus={() => setHover(i)} onBlur={() => setHover(null)}
                onClick={() => onSelect?.(n)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') onSelect?.(n); }}>
                <Shape type={n.type} r={focus ? 9 : 6} fill={c} stroke={focus ? 'var(--color-ink)' : n.malicious ? 'var(--color-block)' : 'var(--color-surface)'} />
                {show && <text y={focus ? 20 : 16} fontSize={focus ? 11 : 9} fill={focus ? 'var(--color-ink)' : 'var(--color-muted)'} textAnchor="middle" paintOrder="stroke" stroke="var(--color-surface)" strokeWidth="3" fontFamily="var(--font-mono)">
                  {String(n.label).length > 36 ? String(n.label).slice(0, 34) + '…' : n.label}
                </text>}
              </g>
            );
          })}
        </g>
      </svg>
      <div className="absolute right-2 top-2 flex gap-1">
        <button className="btn h-8 px-2.5 text-[12px]" onClick={() => setView(null)}>Fit</button>
        <button className="btn h-8 w-8 px-0" onClick={() => zoom(0.8)} aria-label="Zoom in">+</button>
        <button className="btn h-8 w-8 px-0" onClick={() => zoom(1.25)} aria-label="Zoom out">−</button>
      </div>
    </div>
  );
}

export function GraphLegend() {
  const items: [string, string][] = [['var(--color-block)', 'known-bad / block'], ['var(--color-quarantine)', 'quarantine range'], ['var(--color-flag)', 'suspicious'], ['var(--color-neutral)', 'neutral'], ['var(--color-accent)', 'brand'], ['var(--color-campaign)', 'campaign']];
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-[12px] text-muted">
      {items.map(([c, t]) => <span key={t} className="inline-flex items-center gap-1.5"><span className="size-2 rounded-full" style={{ background: c }} />{t}</span>)}
      <span className="text-faint">shapes: ● domain ◆ IP ▲ nameserver ▰ certificate ⬡ ASN/campaign ▭ email</span>
    </div>
  );
}

export function NodePanel({ node }: { node: GraphNode | null }) {
  if (!node) return <p className="text-[13px] text-muted">Select a node to see its details and relationships.</p>;
  const skip = new Set(['id', 'label', 'focus', 'type']);
  return (
    <div className="space-y-3 text-[13px]">
      <div>
        <div className="label">{TYPE_LABEL[node.type] || node.type}</div>
        <div className="mt-1 break-all font-mono">{String(node.id).split(':').slice(1).join(':')}</div>
      </div>
      <dl className="grid grid-cols-[104px_1fr] gap-x-3 gap-y-1.5">
        {Object.entries(node).filter(([k, v]) => !skip.has(k) && v !== null && v !== undefined && v !== '').map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-muted">{k.replace(/_/g, ' ')}</dt>
            <dd className="break-all font-mono text-[12px]">{typeof v === 'boolean' ? (v ? 'yes' : 'no') : String(v)}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
