// Runs only on PhishGraph dashboard origins (see manifest). Lets the dashboard's Setup page connect the extension in one
// click: it announces that the extension is installed and relays {apiKey, options} to the background worker.
(() => {
  const announce = (status) => {
    document.documentElement.dataset.phishgraphExtension = status && status.connected ? 'connected' : 'installed';
    window.postMessage({ type: 'phishgraph:extension', status }, window.location.origin);
  };
  chrome.runtime.sendMessage({ type: 'status' }, announce);
  window.addEventListener('message', (e) => {
    if (e.source !== window || e.origin !== window.location.origin) return;
    const d = e.data || {};
    if (d.type === 'phishgraph:connect') {
      chrome.runtime.sendMessage({ type: 'configure', apiKey: d.apiKey, protectPages: d.protectPages, scanGmail: d.scanGmail }, (r) => {
        window.postMessage({ type: 'phishgraph:connected', result: r }, window.location.origin);
        chrome.runtime.sendMessage({ type: 'status' }, announce);
      });
    } else if (d.type === 'phishgraph:ping') {
      chrome.runtime.sendMessage({ type: 'status' }, announce);
    }
  });
})();
