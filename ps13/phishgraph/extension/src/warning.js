const q = new URLSearchParams(location.search);
const tab = q.get('tab');
const target = q.get('u') || '';
const $ = (id) => document.getElementById(id);
$('url').textContent = target;

chrome.runtime.sendMessage({ type: 'tab-verdict', tab: Number(tab) }, (v) => {
  if (!v) return;
  const pill = $('pill');
  pill.textContent = v.decision;
  pill.className = `pill ${v.decision}`;
  $('score').textContent = Math.round(v.risk_score ?? 0);
  if (v.decision === 'FLAG') {
    $('title').textContent = 'This page looks suspicious';
    $('lede').textContent = 'Check the address carefully before entering any information.';
  }
  const ul = $('reasons');
  for (const r of (v.reasons || []).slice(0, 8)) {
    const li = document.createElement('li');
    const c = document.createElement('span');
    c.className = 'cat';
    c.textContent = r.category;
    const t = document.createElement('span');
    t.textContent = r.text;
    li.append(c, t);
    ul.append(li);
  }
  if (v.offline) {
    const li = document.createElement('li');
    li.innerHTML = '<span class="cat">Note</span><span>PhishGraph server was unreachable; this is an offline structural check only.</span>';
    ul.append(li);
  }
});

$('back').onclick = () => (history.length > 2 ? history.go(-2) : (location.href = 'about:blank'));
$('proceed').onclick = () => chrome.runtime.sendMessage({ type: 'proceed', tab, url: target });
