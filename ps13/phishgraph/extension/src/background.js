// Service worker: checks top-level navigations, answers content-script requests, context menus.
import { analyzeEmail, analyzeUrl, atLeast, localCheck, settings } from './api.js';

const cache = new Map(); // host -> { at, result }
const allowOnce = new Set(); // "tabId|url" the user chose to proceed to
const TTL = 10 * 60 * 1000;
const SKIP = /^(chrome|chrome-extension|edge|about|data|blob|file|view-source|devtools):/;

async function verdictFor(url) {
  const host = new URL(url).hostname;
  const hit = cache.get(url) || cache.get(host);
  if (hit && Date.now() - hit.at < TTL) return hit.result;
  let result;
  try {
    result = await analyzeUrl(url);
  } catch (e) {
    result = localCheck(url) || { decision: 'UNKNOWN', error: String(e.message || e) };
  }
  cache.set(url, { at: Date.now(), result });
  if (result.decision === 'ALLOW') cache.set(host, { at: Date.now(), result });
  if (cache.size > 2000) cache.delete(cache.keys().next().value);
  return result;
}

function badge(tabId, decision) {
  const map = { BLOCK: ['!', '#e5484d'], QUARANTINE: ['!', '#f0703c'], FLAG: ['?', '#d99a06'], ALLOW: ['', '#2f9e63'] };
  const [text, color] = map[decision] || ['', '#6b7280'];
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

chrome.webNavigation.onCommitted.addListener(async (d) => {
  if (d.frameId !== 0 || SKIP.test(d.url)) return;
  const s = await settings();
  if (!s.protectPages) return;
  if (d.url.startsWith(s.server)) return; // never scan the PhishGraph dashboard itself
  const key = `${d.tabId}|${d.url}`;
  const r = await verdictFor(d.url);
  badge(d.tabId, r.decision);
  await chrome.storage.session.set({ [`tab:${d.tabId}`]: { url: d.url, ...r } });
  if (allowOnce.has(key)) return;
  if (r.decision && atLeast(r.decision, s.blockThreshold)) {
    const w = chrome.runtime.getURL('src/warning.html') + `?tab=${d.tabId}&u=${encodeURIComponent(d.url)}`;
    chrome.tabs.update(d.tabId, { url: w });
  }
});

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    if (msg.type === 'analyze-email') {
      const s = await settings();
      if (!s.scanGmail) return reply({ skipped: 'gmail-scanning-off' });
      try { reply(await analyzeEmail(msg.payload)); } catch (e) { reply({ error: String(e.message || e) }); }
    } else if (msg.type === 'proceed') {
      allowOnce.add(`${msg.tab}|${msg.url}`);
      chrome.tabs.update(Number(msg.tab), { url: msg.url });
      reply({ ok: true });
    } else if (msg.type === 'tab-verdict') {
      const k = `tab:${msg.tab}`;
      reply((await chrome.storage.session.get(k))[k] || null);
    } else if (msg.type === 'check-url') {
      reply(await verdictFor(msg.url));
    }
  })();
  return true;
});

chrome.runtime.onInstalled.addListener((info) => {
  chrome.contextMenus.create({ id: 'pg-link', title: 'Check link with PhishGraph', contexts: ['link'] });
  chrome.contextMenus.create({ id: 'pg-text', title: 'Check selected text with PhishGraph', contexts: ['selection'] });
  if (info.reason === 'install') chrome.runtime.openOptionsPage();
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  let r;
  try {
    r = info.menuItemId === 'pg-link' ? await analyzeUrl(info.linkUrl) : await analyzeEmail({ subject: '', sender: '', body: info.selectionText || '', channel: 'other' });
  } catch (e) {
    r = { error: String(e.message || e) };
  }
  await chrome.storage.session.set({ lastCheck: { at: Date.now(), target: info.linkUrl || (info.selectionText || '').slice(0, 120), ...r } });
  chrome.action.openPopup?.();
});
