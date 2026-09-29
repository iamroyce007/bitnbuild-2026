import { settings } from './api.js';

const $ = (id) => document.getElementById(id);
const s = await settings();
$('openSetup').href = s.server;
{
  $('headline').textContent = 'PhishGraph Guard is active';
  $('lede').textContent = 'Works out of the box: pages you open are checked against the PhishGraph server below. Change what is scanned here.';
  $('status').innerHTML = '';
  const dot = document.createElement('span');
  dot.className = `status ${s.protectPages ? 'on' : 'off'}`;
  dot.innerHTML = '<i></i>';
  dot.append(s.protectPages ? 'Protecting' : 'Paused');
  const t = document.createElement('span');
  t.className = 'mono muted';
  t.style.fontSize = '12px';
  t.textContent = s.server;
  $('status').append(dot, t);
}
$('server').value = s.server;
$('apiKey').value = s.apiKey;
$('protectPages').checked = s.protectPages;
$('scanGmail').checked = s.scanGmail;
$('blockThreshold').value = s.blockThreshold;

for (const id of ['protectPages', 'scanGmail', 'blockThreshold']) {
  $(id).onchange = () => chrome.storage.sync.set({ [id]: $(id).type === 'checkbox' ? $(id).checked : $(id).value });
}

$('save').onclick = async () => {
  const msg = $('msg');
  let server = $('server').value.trim().replace(/\/+$/, '');
  if (!/^https?:\/\//.test(server)) server = `https://${server}`;
  const origin = new URL(server).origin + '/*';
  const granted = await chrome.permissions.request({ origins: [origin] }); // only the user's own server
  if (!granted) { msg.textContent = 'Permission to reach the server was not granted.'; return; }
  await chrome.storage.sync.set({ server, apiKey: $('apiKey').value.trim(), connected: true });
  msg.textContent = 'Testing…';
  try {
    const r = await fetch(`${server}/api/v1/analyze/url`, { method: 'POST', headers: { 'content-type': 'application/json', ...($('apiKey').value.trim() ? { 'X-API-Key': $('apiKey').value.trim() } : {}) },
      body: JSON.stringify({ url: 'https://www.google.com/' }) });
    msg.textContent = r.ok ? 'Connected. Protection is active.' : r.status === 401 ? 'This server is private and needs an access key.' : `Server answered HTTP ${r.status}.`;
  } catch (e) {
    msg.textContent = `Could not reach ${server}.`;
  }
};
