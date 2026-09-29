import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Icon, NAV_GROUPS } from './ui';

type Cmd = { id: string; label: string; hint: string; icon: string; run: () => void };
const looksLikeTarget = (v: string) => !/\s/.test(v) && /^(https?:\/\/)?[\w-]+(\.[\w-]+)+/i.test(v);

/** ⌘K / Ctrl+K palette: check a URL or domain, jump to any page, or run a common action. Keyboard first. */
export default function CommandPalette({ open, setOpen, actions }: { open: boolean; setOpen: (o: boolean) => void; actions: Cmd[] }) {
  const nav = useNavigate();
  const [q, setQ] = useState('');
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const opener = useRef<Element | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setOpen(!open); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, setOpen]);

  useEffect(() => {
    if (open) { opener.current = document.activeElement; setQ(''); setSel(0); }
    else if (opener.current instanceof HTMLElement) opener.current.focus(); // focus returns where it came from
  }, [open]);

  const items = useMemo(() => {
    const v = q.trim();
    const out: Cmd[] = [];
    if (v && looksLikeTarget(v)) out.push({ id: 'inv', label: `Investigate ${v}`, hint: 'DNS, age, TLS, graph, look-alikes', icon: 'investigate', run: () => nav(`/investigate?url=${encodeURIComponent(v)}`) });
    const pages: Cmd[] = NAV_GROUPS.flatMap((g) => g.items.map(([to, icon, label]) => ({ id: to, label, hint: g.group, icon, run: () => nav(to) })));
    const all = [...actions, ...pages];
    const needle = v.toLowerCase();
    out.push(...(needle ? all.filter((c) => `${c.label} ${c.hint}`.toLowerCase().includes(needle)) : all));
    return out.slice(0, 12);
  }, [q, actions, nav]);

  if (!open) return null;
  const go = (c?: Cmd) => { if (!c) return; setOpen(false); c.run(); };
  return (
    <div className="fixed inset-0 z-50 grid place-items-start bg-ink/30 px-4 pt-[12vh] backdrop-blur-[2px]" style={{ animation: 'fade .14s ease-out' }} onMouseDown={() => setOpen(false)}>
      <div role="dialog" aria-modal="true" aria-label="Command palette" className="pop card mx-auto w-full max-w-xl overflow-hidden shadow-2xl" onMouseDown={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 border-b border-line px-3">
          <Icon name="search" className="size-4 text-faint" />
          <input ref={input} autoFocus value={q} onChange={(e) => { setQ(e.target.value); setSel(0); }} placeholder="Paste a URL or domain, or type a page name"
            aria-label="Command" aria-controls="cmd-list" aria-activedescendant={items[sel] ? `cmd-${items[sel].id}` : undefined}
            className="h-12 flex-1 bg-transparent text-[15px] outline-none placeholder:text-faint focus-visible:outline-none"
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') { e.preventDefault(); setSel((s) => Math.min(items.length - 1, s + 1)); }
              else if (e.key === 'ArrowUp') { e.preventDefault(); setSel((s) => Math.max(0, s - 1)); }
              else if (e.key === 'Enter') { e.preventDefault(); go(items[sel]); }
              else if (e.key === 'Escape') setOpen(false);
            }} />
          <kbd className="rounded-[3px] border border-line px-1.5 font-mono text-[11px] text-faint">esc</kbd>
        </div>
        <ul id="cmd-list" role="listbox" className="max-h-[50vh] overflow-y-auto p-1.5">
          {items.length === 0 && <li className="px-3 py-6 text-center text-[13px] text-muted">Nothing matches. Paste a full domain to investigate it.</li>}
          {items.map((c, i) => (
            <li key={c.id} id={`cmd-${c.id}`} role="option" aria-selected={i === sel} onMouseEnter={() => setSel(i)} onClick={() => go(c)}
              className={`flex cursor-pointer items-center gap-3 rounded-[3px] px-3 py-2 text-[13px] ${i === sel ? 'bg-surface-2' : ''}`}>
              <Icon name={c.icon} className="size-4 text-muted" />
              <span className={`flex-1 truncate ${i === sel ? 'font-medium' : ''}`}>{c.label}</span>
              <span className="eyebrow">{c.hint}</span>
            </li>
          ))}
        </ul>
        <div className="flex gap-4 border-t border-line bg-surface-2 px-3 py-1.5 font-mono text-[11px] text-faint">
          <span>↑↓ move</span><span>↵ open</span><span>⌘K toggle</span>
        </div>
      </div>
    </div>
  );
}
