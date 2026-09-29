import { reasonItems, riskDial } from './dial.js';

const q = new URLSearchParams(location.search);
const tab = q.get('tab');
const target = q.get('u') || '';
const $ = (id) => document.getElementById(id);
const RULE = { FLAG: 'var(--flag)', QUARANTINE: 'var(--quar)', BLOCK: 'var(--block)' };
$('url').textContent = target;

chrome.runtime.sendMessage({ type: 'tab-verdict', tab: Number(tab) }, (v) => {
  if (!v) return;
  const pill = $('pill');
  pill.textContent = v.decision;
  pill.className = `pill ${v.decision}`;
  $('frame').style.borderTopColor = RULE[v.decision] || 'var(--block)';
  $('dial').append(riskDial(v.risk_score ?? 0, v.decision, 160));
  if (v.decision === 'FLAG') {
    $('titleMark').textContent = 'This page looks suspicious';
    $('lede').textContent = 'Check the address carefully before entering any information.';
  }
  const items = reasonItems((v.reasons || []).slice(0, 8));
  if (v.offline) items.push(...reasonItems([{ category: 'Note', text: 'The PhishGraph server was unreachable, so this is an offline structural check only.' }]));
  $('reasons').append(...items);
});

$('back').onclick = () => (history.length > 2 ? history.go(-2) : (location.href = 'about:blank'));
$('proceed').onclick = () => chrome.runtime.sendMessage({ type: 'proceed', tab, url: target });
