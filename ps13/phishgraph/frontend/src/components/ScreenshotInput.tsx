import { useEffect, useRef, useState } from 'react';
import { api, type Extraction } from '../lib/api';
import { readScreenshot, type OcrLang, type OcrProgress } from '../lib/ocr';
import { CountUp, ErrorBox } from './ui';

type Fields = Pick<Extraction, 'channel' | 'sender' | 'subject' | 'body'>;
type Stage = 'pick' | 'reading' | 'review';

const LANGS: [OcrLang, string][] = [['eng', 'English'], ['hin', 'Hindi'], ['tam', 'Tamil']];
const STATUS: Record<string, string> = {
  'loading tesseract core': 'Loading text recognition engine',
  'initializing tesseract': 'Starting text recognition',
  'loading language traineddata': 'Loading language data (first time only)',
  'initializing api': 'Starting text recognition',
  'recognizing text': 'Reading text',
};

function EntityRow({ label, items, mono = true }: { label: string; items: string[]; mono?: boolean }) {
  if (!items.length) return null;
  return (
    <tr>
      <th scope="row" className="w-32 py-1.5 pr-3 text-left align-top text-[12px] font-medium text-muted">{label} <span className="text-faint">({items.length})</span></th>
      <td className="py-1.5">
        <ul className="flex flex-wrap gap-1">
          {items.map((v, i) => <li key={v} className={`pop break-all rounded-[3px] border border-line bg-surface-2 px-1.5 py-px text-[12px] ${mono ? 'font-mono' : ''}`} style={{ animationDelay: `${i * 40}ms` }}>{v}</li>)}
        </ul>
      </td>
    </tr>
  );
}

/** Screenshot of an SMS / WhatsApp chat / email -> OCR in the browser -> server extracts the message layout and every
 *  entity -> the person reviews and corrects it -> analyse. Only text is sent; the image stays on the device. */
export default function ScreenshotInput({ busy, onAnalyze }: { busy: boolean; onAnalyze: (f: Fields) => void }) {
  const [stage, setStage] = useState<Stage>('pick');
  const [preview, setPreview] = useState<string | null>(null);
  const [langs, setLangs] = useState<OcrLang[]>(['eng']);
  const [hint, setHint] = useState<'auto' | 'sms' | 'email'>('auto');
  const [prog, setProg] = useState<OcrProgress>({ status: '', progress: 0 });
  const [ocr, setOcr] = useState<{ text: string; confidence: number; inverted: boolean } | null>(null);
  const [ex, setEx] = useState<Extraction | null>(null);
  const [f, setF] = useState<Fields>({ channel: 'sms', sender: '', subject: '', body: '' });
  const [err, setErr] = useState<unknown>(null);
  const [drag, setDrag] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const edited = useRef(false);

  useEffect(() => () => { if (preview) URL.revokeObjectURL(preview); }, [preview]);

  const read = async (file: Blob) => {
    if (!file.type.startsWith('image/')) { setErr(new Error('That file is not an image. Use a PNG, JPEG or WebP screenshot.')); return; }
    if (file.size > 15_000_000) { setErr(new Error('That image is larger than 15 MB.')); return; }
    setErr(null); setEx(null); setOcr(null);
    setPreview(URL.createObjectURL(file));
    setStage('reading');
    try {
      const r = await readScreenshot(file, langs, setProg);
      setOcr(r);
      setProg({ status: 'Extracting sender, links and other entities', progress: 1 });
      const x = await api.extract(r.text, hint, r.confidence);
      setEx(x);
      setF({ channel: x.channel, sender: x.sender, subject: x.subject, body: x.body });
      edited.current = false;
      setStage('review');
    } catch (e) {
      setErr(e);
      setStage('pick');
    }
  };

  // paste a screenshot from the clipboard anywhere on the page
  useEffect(() => {
    const onPaste = (e: ClipboardEvent) => {
      const item = [...(e.clipboardData?.items || [])].find((i) => i.type.startsWith('image/'));
      const file = item?.getAsFile();
      if (file && stage !== 'reading') { e.preventDefault(); read(file); }
    };
    window.addEventListener('paste', onPaste);
    return () => window.removeEventListener('paste', onPaste);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stage, langs, hint]);

  // after the person corrects a field, re-extract entities from exactly what they typed
  useEffect(() => {
    if (stage !== 'review' || !edited.current) return;
    const t = window.setTimeout(async () => {
      try { setEx(await api.extract('', hint, ocr?.confidence, f)); } catch { /* keep the previous list */ }
    }, 600);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [f]);

  const set = (k: keyof Fields) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    edited.current = true;
    setF({ ...f, [k]: e.target.value } as Fields);
  };
  // explicit button for people who do not know the keyboard shortcut (needs the async Clipboard API + permission)
  const pasteFromClipboard = async () => {
    setErr(null);
    try {
      if (!navigator.clipboard?.read) throw new Error('This browser cannot read images from the clipboard. Press Ctrl+V / ⌘V instead.');
      for (const item of await navigator.clipboard.read()) {
        const type = item.types.find((t) => t.startsWith('image/'));
        if (type) { read(await item.getType(type)); return; }
      }
      const text = await navigator.clipboard.readText().catch(() => '');
      if (text.trim()) { // copied text instead of an image: skip OCR and go straight to entity extraction
        setOcr({ text, confidence: 100, inverted: false });
        const x = await api.extract(text, hint);
        setEx(x); setF({ channel: x.channel, sender: x.sender, subject: x.subject, body: x.body }); edited.current = false; setStage('review');
        return;
      }
      throw new Error('The clipboard has no image or text. Take a screenshot (or copy the message) first.');
    } catch (e) {
      setErr(e instanceof DOMException ? new Error('Clipboard access was blocked. Allow it in the browser, or press Ctrl+V / ⌘V.') : e);
    }
  };
  const reset = () => { setStage('pick'); setPreview(null); setEx(null); setOcr(null); setErr(null); };
  const e = ex?.entities;
  const total = e ? e.urls.length + e.emails.length + e.phones.length + e.upi_ids.length + e.crypto_wallets.length + e.amounts.length + e.codes.length + e.deadlines.length + e.brands_claimed.length + (e.sender_header ? 1 : 0) : 0;

  if (stage === 'pick') return (
    <div className="space-y-3">
      <div
        onDragOver={(ev) => { ev.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
        onDrop={(ev) => { ev.preventDefault(); setDrag(false); const file = ev.dataTransfer.files[0]; if (file) read(file); }}
        className={`grid place-items-center rounded-[3px] border-2 border-dashed px-4 py-9 text-center transition-[border-color,background-color,transform] duration-200 ${drag ? 'scale-[1.01] border-primary bg-mark/15' : 'border-line-strong bg-surface-2/60'}`}>
        <svg viewBox="0 0 48 48" className="mb-2 size-11 text-muted" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <rect x="13" y="4" width="22" height="40" rx="4" /><path d="M21 8h6M18 16h12M18 21h9M18 26h11" /><circle cx="33" cy="33" r="7" fill="var(--color-mark)" stroke="var(--color-ink)" /><path d="m38 38 4 4" stroke="var(--color-ink)" />
        </svg>
        <p className="text-[15px] font-semibold">Drop a <span className="hl">screenshot</span> here</p>
        <p className="mt-1 text-[12px] text-muted">SMS, WhatsApp, Gmail or Outlook. You can also paste it with Ctrl+V / ⌘V.</p>
        <div className="mt-3 flex flex-wrap justify-center gap-2">
          <button type="button" className="btn btn-primary" onClick={() => fileRef.current?.click()}>Choose image</button>
          <button type="button" className="btn" onClick={pasteFromClipboard}>Paste from clipboard</button>
        </div>
        <input ref={fileRef} type="file" accept="image/png,image/jpeg,image/webp" className="sr-only" aria-label="Screenshot file"
          onChange={(ev) => { const file = ev.target.files?.[0]; if (file) read(file); ev.target.value = ''; }} />
      </div>
      <fieldset className="grid gap-3 sm:grid-cols-2">
        <div>
          <legend className="label mb-1">Text in the screenshot</legend>
          <div className="flex flex-wrap gap-3 text-[13px]">
            {LANGS.map(([code, name]) => (
              <label key={code} className="flex items-center gap-1.5">
                <input type="checkbox" className="accent-accent" checked={langs.includes(code)} disabled={code === 'eng'}
                  onChange={(ev) => setLangs(ev.target.checked ? [...langs, code] : langs.filter((l) => l !== code))} />{name}
              </label>
            ))}
          </div>
        </div>
        <label className="block"><span className="label">It is a screenshot of</span>
          <select className="input mt-1" value={hint} onChange={(ev) => setHint(ev.target.value as typeof hint)}>
            <option value="auto">Detect automatically</option><option value="sms">SMS or chat</option><option value="email">Email</option>
          </select>
        </label>
      </fieldset>
      <p className="text-[12px] text-faint">The image is read inside your browser and never uploaded. Only the recognised text is sent for analysis. The first read downloads the recognition engine (a few MB), which your browser then caches.</p>
      {err ? <ErrorBox error={err} /> : null}
    </div>
  );

  if (stage === 'reading') return (
    <div className="space-y-3" aria-live="polite">
      {preview && (
        <div className="relative overflow-hidden rounded-[3px] border border-line bg-surface-2">
          <img src={preview} alt="Screenshot being read" className="max-h-72 w-full object-contain" />
          <div className="scan-beam" aria-hidden="true" />
        </div>
      )}
      <div className="flex items-baseline justify-between gap-3 text-[13px]"><span>{STATUS[prog.status] || prog.status || 'Working'}…</span><span className="font-mono text-[12px] text-faint">{Math.round(prog.progress * 100)}%</span></div>
      <div className="h-1.5 overflow-hidden rounded-full bg-surface-2" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(prog.progress * 100)}>
        <div className="h-full bg-accent transition-[width] duration-200" style={{ width: `${Math.max(3, prog.progress * 100)}%` }} />
      </div>
    </div>
  );

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3">
        {preview && <img src={preview} alt="Uploaded screenshot" className="h-28 w-20 shrink-0 rounded border border-line object-cover object-top" />}
        <div className="min-w-0 text-[13px]">
          <div className="font-semibold"><span className="hl">Check what was read</span></div>
          <p className="text-muted">Correct anything the text recognition got wrong, then analyse.</p>
          <p className="mt-1 text-[12px] text-faint">Recognition confidence {ocr ? Math.round(ocr.confidence) : '–'}%{ocr?.inverted ? ' · dark-mode image inverted' : ''}</p>
          <button type="button" className="mt-1 text-[12px] text-accent hover:underline" onClick={reset}>Use a different screenshot</button>
        </div>
      </div>

      {ex?.warnings.map((w) => <div key={w} role="note" className="rounded border border-flag/40 border-l-[3px] bg-flag/5 px-3 py-1.5 text-[13px]">{w}</div>)}

      <div className="grid grid-cols-[1fr_2fr] gap-2">
        <label className="block"><span className="label">Type</span>
          <select className="input mt-1" value={f.channel} onChange={set('channel')}>
            <option value="sms">SMS</option><option value="whatsapp">WhatsApp</option><option value="email">Email</option>
          </select>
        </label>
        <label className="block"><span className="label">{f.channel === 'email' ? 'From' : 'Sender'}</span>
          <input className="input mt-1 font-mono" value={f.sender} onChange={set('sender')} placeholder={f.channel === 'email' ? 'Name <address@domain>' : 'Number or sender ID'} />
        </label>
      </div>
      {f.channel === 'email' && <label className="block"><span className="label">Subject</span><input className="input mt-1" value={f.subject} onChange={set('subject')} /></label>}
      <label className="block"><span className="label">Message</span><textarea className="textarea mt-1 h-40 font-sans" value={f.body} onChange={set('body')} /></label>

      <section aria-labelledby="ent-h" className="rounded border border-line">
        <h3 id="ent-h" className="eyebrow flex justify-between border-b border-line bg-surface-2 px-3 py-1.5"><span>Entities extracted</span><span className="text-ink"><CountUp value={total} /></span></h3>
        <div className="px-3 py-1">
          {total === 0 ? <p className="py-2 text-[13px] text-muted">No links, numbers, payment IDs or brands were found.</p> : (
            <table className="w-full"><tbody>
              <EntityRow label="Links" items={e!.urls.map((u) => u.url)} />
              <EntityRow label="Sender header" items={e!.sender_header ? [`${e!.sender_header.header} (entity ${e!.sender_header.entity})`] : []} />
              <EntityRow label="Brands named" items={e!.brands_claimed} mono={false} />
              <EntityRow label="Email addresses" items={e!.emails} />
              <EntityRow label="Phone numbers" items={e!.phones} />
              <EntityRow label="UPI IDs" items={e!.upi_ids} />
              <EntityRow label="Crypto wallets" items={e!.crypto_wallets} />
              <EntityRow label="Amounts" items={e!.amounts} />
              <EntityRow label="Codes / OTPs" items={e!.codes} />
              <EntityRow label="Deadlines" items={e!.deadlines} mono={false} />
              <EntityRow label="Disguises" items={e!.obfuscation} mono={false} />
            </tbody></table>
          )}
        </div>
      </section>

      {(ex?.repairs.length || ex?.removed_lines.length) ? (
        <details className="text-[12px] text-muted">
          <summary className="cursor-pointer">Clean-up applied to the recognised text</summary>
          <ul className="mt-1 list-disc space-y-0.5 pl-5">
            {ex!.repairs.map((r) => <li key={r}>{r}</li>)}
            {ex!.removed_lines.length > 0 && <li>Ignored screen elements: {ex!.removed_lines.map((l) => `"${l}"`).join(', ')}</li>}
          </ul>
        </details>
      ) : null}
      {ocr && (
        <details className="text-[12px] text-muted">
          <summary className="cursor-pointer">Raw recognised text</summary>
          <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap rounded border border-line bg-surface-2 p-2 font-mono text-[12px] text-ink">{ocr.text}</pre>
        </details>
      )}

      <button type="button" className="btn btn-primary w-full" disabled={busy || f.body.trim().length < 4} onClick={() => onAnalyze(f)}>
        {busy ? 'Analysing…' : `Analyse ${f.channel === 'email' ? 'email' : 'message'}`}
      </button>
    </div>
  );
}
