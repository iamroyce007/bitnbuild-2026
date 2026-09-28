import { settings } from './api.js';

const $ = (id) => document.getElementById(id);
const s = await settings();
$('dash').href = s.server;
$('opts').onclick = () => chrome.runtime.openOptionsPage();
$('status').textContent = !s.apiKey ? 'NOT CONFIGURED' : s.protectPages ? 'PROTECTING' : 'PAUSED';

const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
const k = `tab:${tab?.id}`;
const v = (await chrome.storage.session.get(k))[k];
if (v && v.decision) {
  $('pageEmpty').hidden = true;
  $('pageBody').hidden = false;
  $('pill').textContent = v.decision;
  $('pill').className = `pill ${v.decision}`;
  $('score').textContent = v.risk_score != null ? Math.round(v.risk_score) : '--';
  $('host').textContent = v.url;
  for (const r of (v.reasons || []).slice(0, v.decision === 'ALLOW' ? 1 : 4)) {
    const li = document.createElement('li');
    const c = document.createElement('span');
    c.className = 'cat';
    c.textContent = r.category;
    const t = document.createElement('span');
    t.textContent = r.text;
    li.append(c, t);
    $('reasons').append(li);
  }
  if (v.error) $('host').textContent += `  (server: ${v.error})`;
}

const { lastCheck } = await chrome.storage.session.get('lastCheck');
if (lastCheck && Date.now() - lastCheck.at < 10 * 60 * 1000) {
  $('last').hidden = false;
  $('lastTarget').textContent = lastCheck.target;
  $('lastPill').textContent = lastCheck.decision || 'ERROR';
  $('lastPill').className = `pill ${lastCheck.decision || 'UNKNOWN'}`;
  $('lastScore').textContent = lastCheck.risk_score != null ? Math.round(lastCheck.risk_score) : '';
}
