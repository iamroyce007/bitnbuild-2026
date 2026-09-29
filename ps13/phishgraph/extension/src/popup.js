import { settings } from './api.js';
import { reasonItems, riskDial } from './dial.js';

const $ = (id) => document.getElementById(id);
const HEADLINE = { ALLOW: 'No phishing indicators on this page', FLAG: 'Suspicious: check the address before typing', QUARANTINE: 'Likely phishing: do not enter anything', BLOCK: 'Phishing: leave this page' };
const s = await settings();
$('dash').href = s.server;
$('opts').onclick = () => chrome.runtime.openOptionsPage();
$('status').className = `status ${s.protectPages ? 'on' : 'off'}`;
$('statusText').textContent = s.protectPages ? 'Protecting' : 'Paused';

const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
const k = `tab:${tab?.id}`;
const v = (await chrome.storage.session.get(k))[k];
if (v && v.decision) {
  $('pageEmpty').hidden = true;
  $('pageBody').hidden = false;
  $('page').style.borderTop = `3px solid var(--${{ ALLOW: 'allow', FLAG: 'flag', QUARANTINE: 'quar', BLOCK: 'block' }[v.decision] || 'line-strong'})`;
  $('dial').append(riskDial(v.risk_score ?? 0, v.decision, 112));
  const h = document.createElement('span');
  h.textContent = HEADLINE[v.decision] || 'Checked';
  if (v.decision !== 'ALLOW') h.className = 'hl';
  $('headline').append(h);
  $('pill').textContent = v.decision;
  $('pill').className = `pill ${v.decision}`;
  $('host').textContent = v.url + (v.error ? `  (server: ${v.error})` : '');
  $('reasons').append(...reasonItems((v.reasons || []).slice(0, v.decision === 'ALLOW' ? 1 : 4)));
}

const { lastCheck } = await chrome.storage.session.get('lastCheck');
if (lastCheck && Date.now() - lastCheck.at < 10 * 60 * 1000) {
  $('last').hidden = false;
  $('lastTarget').textContent = lastCheck.target;
  $('lastPill').textContent = lastCheck.decision ? `${lastCheck.decision} ${lastCheck.risk_score != null ? Math.round(lastCheck.risk_score) : ''}`.trim() : 'ERROR';
  $('lastPill').className = `pill ${lastCheck.decision || 'UNKNOWN'}`;
}
