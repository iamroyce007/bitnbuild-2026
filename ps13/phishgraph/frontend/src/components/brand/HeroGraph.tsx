import { useEffect, useRef } from 'react';

/** Illustrative network behind the hero (NOT application data; the page captions it). Canvas, ~50 nodes, packets
 *  travelling along edges, a few threat nodes pulsing. Pauses when offscreen or the tab is hidden; a single static
 *  frame under prefers-reduced-motion. Deterministic seed, so it looks the same on every visit. */
export default function HeroGraph({ className = '' }: { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const cv = ref.current!;
    const ctx = cv.getContext('2d')!;
    let raf = 0, visible = true, w = 0, h = 0;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let seed = 7;
    const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
    const css = (v: string) => getComputedStyle(document.documentElement).getPropertyValue(v).trim() || '#38bdf8';
    const N = 52;
    const nodes = Array.from({ length: N }, (_, i) => ({ x: rnd(), y: rnd(), r: 1.4 + rnd() * 2.2, threat: i % 9 === 0, hub: i % 13 === 0, ph: rnd() * Math.PI * 2 }));
    const edges: [number, number][] = [];
    nodes.forEach((a, i) => {
      const near = nodes.map((b, j) => [j, (a.x - b.x) ** 2 + (a.y - b.y) ** 2] as const).filter(([j]) => j !== i).sort((p, q) => p[1] - q[1]).slice(0, 2);
      near.forEach(([j]) => { if (!edges.some(([p, q]) => (p === i && q === j) || (p === j && q === i))) edges.push([i, j]); });
    });
    const packets = Array.from({ length: 18 }, () => ({ e: Math.floor(rnd() * edges.length), t: rnd(), v: 0.0025 + rnd() * 0.004 }));
    const resize = () => {
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      w = cv.clientWidth; h = cv.clientHeight;
      cv.width = w * dpr; cv.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    const accent = css('--color-accent'), block = css('--color-block'), ink = css('--color-ink');
    const P = (n: (typeof nodes)[number], time: number) => [
      (0.04 + n.x * 0.92) * w + Math.sin(time / 4000 + n.ph) * 6,
      (0.06 + n.y * 0.88) * h + Math.cos(time / 5000 + n.ph) * 5,
    ];
    const draw = (time: number) => {
      ctx.clearRect(0, 0, w, h);
      const pos = nodes.map((n) => P(n, time));
      ctx.lineWidth = 1;
      for (const [a, b] of edges) {
        const bad = nodes[a].threat || nodes[b].threat;
        ctx.strokeStyle = bad ? `${block}33` : `${accent}22`;
        ctx.beginPath(); ctx.moveTo(pos[a][0], pos[a][1]); ctx.lineTo(pos[b][0], pos[b][1]); ctx.stroke();
      }
      for (const p of packets) {
        const [a, b] = edges[p.e];
        const x = pos[a][0] + (pos[b][0] - pos[a][0]) * p.t, y = pos[a][1] + (pos[b][1] - pos[a][1]) * p.t;
        ctx.fillStyle = nodes[a].threat || nodes[b].threat ? block : accent;
        ctx.globalAlpha = 0.85; ctx.beginPath(); ctx.arc(x, y, 1.6, 0, Math.PI * 2); ctx.fill(); ctx.globalAlpha = 1;
        if (!reduced) { p.t += p.v; if (p.t > 1) { p.t = 0; p.e = Math.floor(rnd() * edges.length); } }
      }
      nodes.forEach((n, i) => {
        const [x, y] = pos[i];
        if (n.threat) {
          const k = reduced ? 0.5 : ((time / 2000 + n.ph) % 1);
          ctx.strokeStyle = block; ctx.globalAlpha = 0.5 * (1 - k); ctx.beginPath(); ctx.arc(x, y, n.r + k * 12, 0, Math.PI * 2); ctx.stroke(); ctx.globalAlpha = 1;
        }
        ctx.fillStyle = n.threat ? block : n.hub ? accent : ink;
        ctx.globalAlpha = n.threat || n.hub ? 0.95 : 0.45;
        ctx.beginPath(); ctx.arc(x, y, n.hub ? n.r + 1.5 : n.r, 0, Math.PI * 2); ctx.fill(); ctx.globalAlpha = 1;
      });
    };
    const loop = (t: number) => { if (visible && !document.hidden) draw(t); raf = requestAnimationFrame(loop); };
    resize();
    draw(performance.now()); // always paint a first frame, even if the tab starts hidden
    const ro = new ResizeObserver(() => { resize(); draw(performance.now()); });
    ro.observe(cv);
    const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting; });
    io.observe(cv);
    if (!reduced) raf = requestAnimationFrame(loop);
    return () => { cancelAnimationFrame(raf); ro.disconnect(); io.disconnect(); };
  }, []);
  return <canvas ref={ref} className={className} aria-hidden="true" />;
}
