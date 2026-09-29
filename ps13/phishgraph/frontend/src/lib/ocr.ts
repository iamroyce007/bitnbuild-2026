// In-browser OCR for message screenshots. The image never leaves the device: only the recognised text is sent
// to the server. tesseract.js is imported on demand (its own chunk), and its WebAssembly engine and language
// data are fetched from the jsDelivr CDN the first time a screenshot is read, then cached by the browser.

export type OcrLang = 'eng' | 'hin' | 'tam';
export type OcrProgress = { status: string; progress: number };
export type OcrResult = { text: string; confidence: number; inverted: boolean; scaled: number };

/** Upscale small crops, convert to greyscale and turn dark-mode screenshots (light text on dark) into dark-on-light,
 *  which is what the OCR engine reads best. */
async function prepare(file: Blob): Promise<{ canvas: HTMLCanvasElement; inverted: boolean; scaled: number }> {
  const bmp = await createImageBitmap(file);
  const scaled = Math.min(3, Math.max(1, 1400 / bmp.width));
  const canvas = document.createElement('canvas');
  canvas.width = Math.round(bmp.width * scaled);
  canvas.height = Math.round(bmp.height * scaled);
  const ctx = canvas.getContext('2d', { willReadFrequently: true })!;
  ctx.imageSmoothingQuality = 'high';
  ctx.drawImage(bmp, 0, 0, canvas.width, canvas.height);
  bmp.close();
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
