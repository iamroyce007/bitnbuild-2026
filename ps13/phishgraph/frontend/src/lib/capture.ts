// Getting a message into PhishGraph from a screenshot or the clipboard, on any device.
//
// Clipboard rules differ per platform, so `readClipboard` must be called straight from a tap/click handler:
// - iPhone / iPad Safari: navigator.clipboard.read() shows the system "Paste" bubble; the person taps it.
// - Chrome / Edge (desktop, Android): asks for clipboard permission once.
// - Firefox and older browsers: no image access. We then show a paste target the person can long-press
//   ("Paste") or press Ctrl/Cmd+V in, which works everywhere because it is a real paste event.
import { api, type Extraction } from './api';
import { readScreenshot, type OcrLang, type OcrProgress } from './ocr';

export type Clip = { image?: Blob; text?: string };
export const isTouch = () => typeof window !== 'undefined' && window.matchMedia?.('(pointer: coarse)').matches;
export const isApple = () => /Mac|iPhone|iPad|iPod/.test(navigator.platform) || (navigator.userAgent.includes('Mac') && 'ontouchend' in document);
export const pasteKeys = () => (isApple() ? '⌘V' : 'Ctrl+V');

export class ClipboardUnavailable extends Error {}

/** Read an image (preferred) or text from the clipboard. Throws ClipboardUnavailable when the browser cannot. */
export async function readClipboard(): Promise<Clip> {
  const cb = navigator.clipboard;
  if (cb?.read) {
    try {
      const items = await cb.read(); // must be the first await after the tap (iOS gesture rule)
      for (const item of items) {
        const type = item.types.find((t) => t.startsWith('image/'));
        if (type) return { image: await item.getType(type) };
      }
      for (const item of items) {
        if (item.types.includes('text/plain')) return { text: await (await item.getType('text/plain')).text() };
      }
      return {};
    } catch (e) {
      if (e instanceof DOMException && e.name === 'NotAllowedError') throw new ClipboardUnavailable('denied');
      // fall through to readText (some browsers support only text)
    }
  }
  if (cb?.readText) {
    try { return { text: await cb.readText() }; } catch { /* unavailable */ }
  }
  throw new ClipboardUnavailable('unsupported');
}

/** Image files and pasted text out of a paste event (works on every browser, including iOS long-press Paste). */
export function clipFromPasteEvent(e: ClipboardEvent | React.ClipboardEvent): Clip {
  const dt = e.clipboardData;
  const file = [...(dt?.items || [])].find((i) => i.type.startsWith('image/'))?.getAsFile();
  if (file) return { image: file };
  return { text: dt?.getData('text/plain') || '' };
}

export function checkImage(file: Blob) {
  if (!file.type.startsWith('image/') && file.type !== '') throw new Error('That file is not an image. Use a PNG, JPEG, HEIC or WebP screenshot.');
  if (file.size > 25_000_000) throw new Error('That image is larger than 25 MB.');
}

export type Hint = 'auto' | 'sms' | 'email';

/** Screenshot -> OCR in the browser -> server-side layout + entity extraction. */
export async function extractFromImage(file: Blob, hint: Hint, langs: OcrLang[], onProgress: (p: OcrProgress) => void) {
  checkImage(file);
  const ocr = await readScreenshot(file, langs, onProgress);
  onProgress({ status: 'Extracting sender, links and other entities', progress: 1 });
  const ex = await api.extract(ocr.text, hint, ocr.confidence);
  return { ocr, ex };
}

export const extractFromText = (text: string, hint: Hint): Promise<Extraction> => api.extract(text, hint);

/** Does pasted text look like a whole message with headers (so it should be split into fields)? */
export function looksStructured(text: string) {
  const head = text.split('\n').slice(0, 8).join('\n');
  return text.includes('\n') && (/^(from|subject|to|sent|date):/im.test(head) || /^to me\b/im.test(head) || /^[A-Z]{2}-[A-Z0-9]{6}\b/m.test(head) || /<[^<>\s]+@[^<>\s]+>/.test(head));
}
