import { useRef, useState } from 'react';
import type { Extraction } from '../lib/api';
import { ClipboardUnavailable, extractFromImage, extractFromText, readClipboard, type Clip, type Hint } from '../lib/capture';
import PasteTarget from './PasteTarget';

/** Toolbar above the Email / SMS forms: fill Sender, Subject and Message from a screenshot or the clipboard.
 *  OCR runs in the browser; the server only structures the text (see screenshot_extractor.py). */
export default function FillFromCapture({ hint, onFilled }: { hint: Hint; onFilled: (x: Extraction, from: 'screenshot' | 'text') => void }) {
  const file = useRef<HTMLInputElement>(null);
  const [status, setStatus] = useState('');
  const [pct, setPct] = useState<number | null>(null);
  const [err, setErr] = useState('');
  const [box, setBox] = useState(false);

  const fromImage = async (f: Blob) => {
    setErr(''); setBox(false); setPct(0);
    try {
      const { ex } = await extractFromImage(f, hint, ['eng'], (p) => { setStatus(p.status); setPct(p.progress); });
      onFilled(ex, 'screenshot');
      setStatus(`Filled from the screenshot. Check the fields${ex.warnings.length ? `: ${ex.warnings[0]}` : '.'}`);
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)); setStatus(''); }
    finally { setPct(null); }
  };
  const fromText = async (t: string) => {
    setErr(''); setBox(false);
    if (!t.trim()) { setErr('The clipboard is empty.'); return; }
    try { onFilled(await extractFromText(t, hint), 'text'); setStatus('Filled from the clipboard. Check the fields.'); }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
  };
  const use = (c: Clip) => (c.image ? fromImage(c.image) : fromText(c.text || ''));
  const paste = () => {
    setErr('');
    readClipboard().then(use, (e) => (e instanceof ClipboardUnavailable ? setBox(true) : setErr(String(e))));
  };

  return (
    <div className="space-y-2 rounded-[3px] border border-line bg-surface-2/70 p-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="eyebrow mr-auto">Fill fields from</span>
        <button type="button" className="btn h-8 text-[12px]" onClick={() => file.current?.click()} disabled={pct !== null}>Screenshot</button>
        <button type="button" className="btn h-8 text-[12px]" onClick={paste} disabled={pct !== null}>Paste from clipboard</button>
        <input ref={file} type="file" accept="image/*" className="sr-only" tabIndex={-1} aria-label="Screenshot to fill the fields from"
          onChange={(e) => { const f = e.target.files?.[0]; if (f) fromImage(f); e.target.value = ''; }} />
      </div>
      {pct !== null && (
        <div aria-live="polite">
          <div className="mb-1 text-[12px] text-muted">{status || 'Reading'}… {Math.round(pct * 100)}%</div>
          <div className="h-1 overflow-hidden rounded-full bg-surface"><div className="h-full bg-accent transition-[width] duration-200" style={{ width: `${Math.max(3, pct * 100)}%` }} /></div>
        </div>
      )}
      {box && <PasteTarget onClip={use} onCancel={() => setBox(false)} />}
      {pct === null && status && !err && <p className="text-[12px] text-muted" role="status">{status}</p>}
      {err && <p className="text-[12px] text-block" role="alert">{err}</p>}
    </div>
  );
}
