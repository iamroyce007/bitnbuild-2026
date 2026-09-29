// In-browser OCR for message screenshots. The image never leaves the device: only the recognised text is sent
// to the server. tesseract.js is imported on demand (its own chunk), and its WebAssembly engine and language
// data are fetched from the jsDelivr CDN the first time a screenshot is read, then cached by the browser.

export type OcrLang = 'eng' | 'hin' | 'tam';
export type OcrProgress = { status: string; progress: number };
export type OcrResult = { text: string; confidence: number; inverted: boolean; scaled: number };

/** Upscale small crops, convert to greyscale and turn dark-mode screenshots (light text on dark) into dark-on-light,
 *  which is what the OCR engine reads best. */
async function decode(file: Blob): Promise<{ img: CanvasImageSource; w: number; h: number; done: () => void }> {
  try {
    const bmp = await createImageBitmap(file);
    return { img: bmp, w: bmp.width, h: bmp.height, done: () => bmp.close() };
  } catch {
    // some formats (e.g. HEIC on Safari) decode through <img> but not createImageBitmap
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.src = url;
    await img.decode();
    return { img, w: img.naturalWidth, h: img.naturalHeight, done: () => URL.revokeObjectURL(url) };
  }
}

// iOS Safari refuses canvases above ~16.7 megapixels; stay well under it for long, scrolling screenshots
const MAX_PIXELS = 12_000_000;

async function prepare(file: Blob): Promise<{ canvas: HTMLCanvasElement; inverted: boolean; scaled: number }> {
  const { img: source, w, h, done } = await decode(file);
  // small crops are enlarged (OCR wants ~30 px letters); big iPad / desktop captures are reduced to save memory
  let scaled = w < 1400 ? Math.min(3, 1400 / w) : Math.min(1, 2200 / w);
  scaled = Math.min(scaled, Math.sqrt(MAX_PIXELS / (w * h)));
  const canvas = document.createElement('canvas');
  canvas.width = Math.max(1, Math.round(w * scaled));
  canvas.height = Math.max(1, Math.round(h * scaled));
  const ctx = canvas.getContext('2d', { willReadFrequently: true })!;
  ctx.imageSmoothingQuality = 'high';
  ctx.drawImage(source, 0, 0, canvas.width, canvas.height);
  done();
  const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const d = img.data;
  let sum = 0;
  for (let i = 0; i < d.length; i += 4) {
    const y = 0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2];
    d[i] = d[i + 1] = d[i + 2] = y;
    sum += y;
  }
  const inverted = sum / (d.length / 4) < 110;
  if (inverted) for (let i = 0; i < d.length; i += 4) d[i] = d[i + 1] = d[i + 2] = 255 - d[i];
  ctx.putImageData(img, 0, 0);
  return { canvas, inverted, scaled };
}

export async function readScreenshot(file: Blob, langs: OcrLang[], onProgress: (p: OcrProgress) => void): Promise<OcrResult> {
  onProgress({ status: 'Preparing image', progress: 0 });
  const { canvas, inverted, scaled } = await prepare(file);
  onProgress({ status: 'Loading text recognition', progress: 0 });
  const { createWorker } = await import('tesseract.js');
  const worker = await createWorker(langs, 1, {
    logger: (m: { status: string; progress: number }) => onProgress({ status: m.status, progress: m.progress }),
  });
  try {
    const { data } = await worker.recognize(canvas);
    return { text: data.text, confidence: data.confidence, inverted, scaled };
  } finally {
    await worker.terminate();
  }
}
