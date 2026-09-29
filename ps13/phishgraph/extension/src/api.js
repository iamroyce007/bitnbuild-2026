// Shared client for the PhishGraph API + settings. Only talks to the server the user configured.
export const DEFAULTS = { server: 'https://phishgraph.vercel.app', apiKey: '', protectPages: true, scanGmail: false, blockThreshold: 'QUARANTINE' };
// dashboards allowed to hand their connection details to the extension (must match the connect.js content script)
export const DASHBOARD_ORIGINS = ['https://phishgraph.vercel.app', 'http://localhost:8000', 'http://localhost:5173'];
const RANK = { ALLOW: 0, FLAG: 1, QUARANTINE: 2, BLOCK: 3 };

export async function settings() {
  const s = await chrome.storage.sync.get(DEFAULTS);
  return { ...DEFAULTS, ...s, server: (s.server || DEFAULTS.server).replace(/\/+$/, '') };
}

export function atLeast(decision, threshold) {
  return (RANK[decision] ?? 0) >= (RANK[threshold] ?? 2);
}

async function call(path, body) {
  const s = await settings();
  if (!s.apiKey) throw new Error('not-configured');
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await fetch(`${s.server}${path}`, {
      method: 'POST', signal: ctrl.signal,
      headers: { 'content-type': 'application/json', 'X-API-Key': s.apiKey },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`http-${r.status}`);
    return await r.json();
  } finally {
    clearTimeout(t);
  }
}

export const analyzeUrl = (url) => call('/api/v1/analyze/url', { url });
export const analyzeEmail = (msg) => call('/api/v1/analyze/email', msg);

// Offline fallback: only structural red flags that need no reputation data.
export function localCheck(raw) {
  let u;
  try { u = new URL(raw); } catch { return null; }
  const host = u.hostname;
  const reasons = [];
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) reasons.push('Uses a raw IP address instead of a domain name');
  if (host.split('.').some((l) => l.startsWith('xn--'))) reasons.push(`Internationalised domain (punycode): ${host}`);
  if (u.username) reasons.push('Contains "@" before the host; the browser ignores everything before it');
  if (!reasons.length) return null;
  return { decision: 'FLAG', risk_score: 50, reasons: reasons.map((text) => ({ category: 'Link', text })), offline: true };
}

export function dashboardLink(server, id) {
  return `${server}/detections/${encodeURIComponent(id)}`;
}
