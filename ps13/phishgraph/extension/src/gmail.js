// Gmail content script: when a message is opened, ask PhishGraph for a verdict (only if the user enabled
// Gmail scanning) and show an inline banner plus per-link markers. Nothing runs on any other site.
(() => {
  const DONE = 'pgScanned';
  const LABEL = { ALLOW: 'No phishing indicators found', FLAG: 'Suspicious: review before acting', QUARANTINE: 'Likely phishing: do not click links or reply', BLOCK: 'Phishing detected: do not interact' };

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function banner(result) {
    const b = el('div', `pg-banner pg-${(result.decision || 'unknown').toLowerCase()}`);
    const head = el('div', 'pg-head');
    head.append(el('span', 'pg-mark'), el('strong', null, 'PhishGraph'), el('span', 'pg-verdict', LABEL[result.decision] || 'Could not check this message'));
    if (typeof result.risk_score === 'number') head.append(el('span', 'pg-score', `${Math.round(result.risk_score)}/100`));
    b.append(head);
    if (result.error || result.skipped) {
      b.append(el('div', 'pg-sub', result.skipped ? 'Gmail scanning is off (enable it in the extension options).' : `Server unreachable (${result.error}).`));
      return b;
    }
    const reasons = (result.reasons || []).slice(0, result.decision === 'ALLOW' ? 0 : 4);
    if (reasons.length) {
      const ul = el('ul', 'pg-reasons');
      for (const r of reasons) {
        const li = el('li');
        li.append(el('span', 'pg-cat', r.category), document.createTextNode(r.text));
        ul.append(li);
      }
      b.append(ul);
    }
    if (result.campaign && result.campaign.id) b.append(el('div', 'pg-sub', `Part of ${result.campaign.id}`));
    return b;
  }

  function markLinks(body, result) {
    const risky = new Map((result.urls || []).filter((u) => u.score >= 50).map((u) => [u.host, u]));
    for (const a of body.querySelectorAll('a[href]')) {
      let host = '';
      try { host = new URL(a.href).hostname; } catch { continue; }
      const u = risky.get(host);
      if (u) {
        a.classList.add('pg-risky-link');
        a.title = `PhishGraph: risky link (${Math.round(u.score)}/100) — ${(u.rules[0] && u.rules[0].label) || 'suspicious destination'}`;
      }
    }
  }

  function scan(body) {
    if (body.dataset[DONE]) return;
    body.dataset[DONE] = '1';
    const root = body.closest('.adn') || document;
    const who = root.querySelector('span.gD');
    const sender = who ? `${who.getAttribute('name') || who.textContent} <${who.getAttribute('email') || ''}>` : '';
    const subject = (document.querySelector('h2.hP') || {}).innerText || '';
    const payload = { subject, sender, body: body.innerText.slice(0, 60000), html: body.innerHTML.slice(0, 200000), channel: 'email' };
    const slot = el('div', 'pg-slot');
    slot.append(el('div', 'pg-banner pg-pending', 'PhishGraph is checking this message…'));
    body.parentElement.insertBefore(slot, body);
    chrome.runtime.sendMessage({ type: 'analyze-email', payload }, (result) => {
      slot.replaceChildren(banner(result || { error: 'no response' }));
      if (result && result.urls) markLinks(body, result);
    });
  }

  const obs = new MutationObserver(() => document.querySelectorAll('div.a3s:not([data-pg-scanned])').forEach(scan));
  obs.observe(document.body, { childList: true, subtree: true });
})();
