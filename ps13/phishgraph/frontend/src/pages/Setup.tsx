import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useSample } from '../App';
import { PageTitle } from '../components/ui';
import { getKey, setupLink } from '../lib/api';

type ExtState = 'missing' | 'installed' | 'connected';

function Step({ n, title, done, children }: { n: number; title: string; done?: boolean; children: React.ReactNode }) {
  return (
    <li className="card grid grid-cols-[36px_1fr] gap-4 p-5">
      <span className={`grid size-8 place-items-center rounded-full border font-mono text-[13px] ${done ? 'border-allow text-allow' : 'border-line-strong text-muted'}`} aria-hidden="true">{done ? '✓' : n}</span>
      <div className="min-w-0">
        <h2 className="text-[15px] font-semibold">{title}{done && <span className="sr-only"> (done)</span>}</h2>
        <div className="mt-2 space-y-3 text-[13px] text-muted">{children}</div>
      </div>
    </li>
  );
}

export default function Setup() {
  const [ext, setExt] = useState<ExtState>(() => (document.documentElement.dataset.phishgraphExtension as ExtState) || 'missing');
  const [protect, setProtect] = useState(true);
  const [gmail, setGmail] = useState(false);
  const [msg, setMsg] = useState('');
  const [copied, setCopied] = useState('');
  const sample = useSample();

  useEffect(() => {
    const onMsg = (e: MessageEvent) => {
      if (e.source !== window || e.origin !== window.location.origin) return;
      if (e.data?.type === 'phishgraph:extension') setExt(e.data.status?.connected ? 'connected' : 'installed');
      if (e.data?.type === 'phishgraph:connected') setMsg(e.data.result?.ok ? 'Extension connected. It now checks the pages you open.' : `Could not connect: ${e.data.result?.error || 'unknown error'}`);
    };
    window.addEventListener('message', onMsg);
    window.postMessage({ type: 'phishgraph:ping' }, window.location.origin);
    const t = window.setInterval(() => window.postMessage({ type: 'phishgraph:ping' }, window.location.origin), 3000); // notices a fresh install
    return () => { window.removeEventListener('message', onMsg); window.clearInterval(t); };
  }, []);

  const connect = () => {
    setMsg('Connecting…');
    window.postMessage({ type: 'phishgraph:connect', apiKey: getKey(), protectPages: protect, scanGmail: gmail }, window.location.origin);
  };
  const copy = async (text: string, what: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(what);
    window.setTimeout(() => setCopied(''), 2000);
  };

  return (
    <>
      <PageTitle title="Setup" sub="Connect browsers and the Chrome extension. Nothing to configure by hand." />
      <ol className="max-w-3xl space-y-3">
        <Step n={1} title="This browser is connected" done>
          <p>To connect another browser or a teammate, send them the setup link. Anyone with it can use this server, so share it privately.</p>
          <button className="btn" onClick={() => copy(setupLink(), 'link')}>{copied === 'link' ? 'Copied' : 'Copy setup link'}</button>
        </Step>

        <Step n={2} title="Install the Chrome extension" done={ext !== 'missing'}>
          {ext !== 'missing' ? <p>Installed. Continue with step 3.</p> : (
            <>
              <a className="btn btn-primary" href="/downloads/phishgraph-extension.zip" download>Download extension</a>
              <ol className="list-decimal space-y-1 pl-5">
                <li>Unzip the download. You get a folder called <code className="font-mono text-ink">phishgraph-extension</code>.</li>
                <li>Open <button className="font-mono text-accent hover:underline" onClick={() => copy('chrome://extensions', 'ext')}>chrome://extensions</button>{copied === 'ext' && <span className="ml-1 text-allow">copied, paste it in the address bar</span>} and turn on <b className="text-ink">Developer mode</b> (top right).</li>
                <li>Click <b className="text-ink">Load unpacked</b> and choose the folder. Then come back to this page.</li>
              </ol>
              <p className="text-faint">This page notices the extension automatically once it is installed.</p>
            </>
          )}
        </Step>

        <Step n={3} title="Connect the extension" done={ext === 'connected'}>
          {ext === 'missing' ? <p>Install the extension first.</p> : (
            <>
              <label className="flex items-start gap-2 text-ink"><input type="checkbox" className="mt-1 accent-accent" checked={protect} onChange={(e) => setProtect(e.target.checked)} />
                <span>Check the pages I open<span className="block text-muted">Dangerous pages are replaced by a warning that explains why.</span></span></label>
              <label className="flex items-start gap-2 text-ink"><input type="checkbox" className="mt-1 accent-accent" checked={gmail} onChange={(e) => setGmail(e.target.checked)} />
                <span>Scan Gmail messages I open<span className="block text-muted">Adds a verdict banner above each email. The message is sent to this server for analysis.</span></span></label>
              <button className="btn btn-primary" onClick={connect}>{ext === 'connected' ? 'Update extension settings' : 'Connect extension'}</button>
              {msg && <p role="status" className="text-ink">{msg}</p>}
            </>
          )}
        </Step>

        <Step n={4} title="Try it" done={false}>
          <div className="flex flex-wrap gap-2">
            <Link className="btn" to="/analyze">Analyze a suspicious message</Link>
            <Link className="btn" to="/investigate">Investigate a link</Link>
            {!sample.loaded && <button className="btn btn-ghost" onClick={sample.load} disabled={sample.busy}>{sample.busy ? 'Loading sample data…' : 'Load sample data'}</button>}
          </div>
          <p className="text-faint">Sample data adds 27 labelled example messages and fictional attacker infrastructure so every page has something to show. Remove it any time.</p>
        </Step>
      </ol>
    </>
  );
}
