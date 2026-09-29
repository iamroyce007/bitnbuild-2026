import { useEffect, useRef } from 'react';
import { clipFromPasteEvent, isTouch, pasteKeys, type Clip } from '../lib/capture';

/** A box that accepts a real paste: long-press → Paste on iPhone / iPad / Android, or Ctrl/⌘+V on a keyboard.
 *  Used when the browser cannot read the clipboard from a button (Firefox, older Safari, permission denied). */
export default function PasteTarget({ onClip, onCancel }: { onClip: (c: Clip) => void; onCancel: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { ref.current?.focus(); }, []);
  return (
    <div className="pop space-y-2">
      <div ref={ref} contentEditable suppressContentEditableWarning role="textbox" aria-label="Paste your screenshot or message here" tabIndex={0}
        onPaste={(e) => { e.preventDefault(); onClip(clipFromPasteEvent(e)); }}
        onBeforeInput={(e) => e.preventDefault()} onDrop={(e) => e.preventDefault()}
        className="grid min-h-28 cursor-text place-items-center rounded-[3px] border-2 border-dashed border-primary bg-mark/10 px-4 py-6 text-center text-[14px] font-medium caret-transparent outline-none focus:bg-mark/20">
        {isTouch() ? 'Touch and hold here, then tap Paste' : `Click here and press ${pasteKeys()}`}
      </div>
      <p className="text-[12px] text-muted">This browser does not let a button read the clipboard, so paste into the box instead. <button type="button" className="text-accent underline" onClick={onCancel}>Cancel</button></p>
    </div>
  );
}
