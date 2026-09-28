import { useState } from 'react';
import ReportView from '../components/ReportView';
import { ErrorBox, Loading, PageTitle, Section } from '../components/ui';
import { api } from '../lib/api';
import type { Report } from '../lib/types';

type Mode = 'email' | 'sms' | 'url' | 'raw';
const SAMPLES: Record<string, { mode: Mode; subject?: string; sender?: string; body?: string; url?: string }> = {
  'Microsoft look-alike': { mode: 'email', subject: 'Your Microsoft account will be suspended', sender: 'Microsoft Security <security@microsoft-support-alert.xyz>',
    body: 'Dear user, we detected an unusual sign-in to your Microsoft account. Your account will be suspended within 24 hours. Verify your identity immediately at https://microsoft-login-security.example.xyz/verify' },
  'SBI KYC SMS': { mode: 'sms', sender: '+917845123690', body: 'Dear SBI customer, your YONO account will be blocked today due to pending KYC. Update PAN now: sbi-netbanking-kyc.site/kyc . Share OTP with our officer.' },
  'TNEB (Tamil)': { mode: 'sms', sender: '+919003112233', body: 'அன்புள்ள நுகர்வோரே, உங்கள் மின் இணைப்பு இன்று இரவு 9.30 மணிக்கு துண்டிக்கப்படும். உடனடியாக அழைக்கவும் 9876501234 அல்லது tneb-bill-pay.in' },
  'Legitimate notice': { mode: 'email', subject: 'Your GitHub password was reset', sender: 'GitHub <noreply@github.com>', body: 'The password for your GitHub account was recently changed. If you did this, no action is needed. Otherwise visit https://github.com/settings/security' },
  'g00gle vs google': { mode: 'url', url: 'https://g00gle.com/login' },
};

export default function Analyze() {
  const [mode, setMode] = useState<Mode>('email');
  const [f, setF] = useState({ subject: '', sender: '', body: '', url: '', raw: '' });
  const [deep, setDeep] = useState(true);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [rep, setRep] = useState<Report | null>(null);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value });

  const run = async (e?: React.FormEvent) => {
    e?.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const r = mode === 'url' ? await api.analyzeUrl(f.url.trim(), deep)
        : mode === 'raw' ? await api.analyzeEmail({ raw: f.raw, deep })
        : await api.analyzeEmail({ subject: f.subject, sender: f.sender, body: f.body, channel: mode === 'sms' ? 'sms' : 'email', deep });
      setRep(r.report);
    } catch (x) {
      setErr(x);
    } finally {
      setBusy(false);
    }
  };
  const canRun = mode === 'url' ? f.url.trim().length > 3 : mode === 'raw' ? f.raw.length > 20 : f.body.trim().length > 3;
  return (
    <>
      <PageTitle title="Analyze message" sub="Paste an email, SMS / WhatsApp message, a raw .eml, or a single link." />
      <div className="grid gap-5 xl:grid-cols-[440px_minmax(0,1fr)]">
        <Section title="Input">
          <form onSubmit={run} className="space-y-3">
            <div className="grid grid-cols-4 gap-1 rounded-md border border-line p-1" role="tablist" aria-label="Input type">
              {(['email', 'sms', 'url', 'raw'] as Mode[]).map((m) => (
                <button type="button" key={m} role="tab" aria-selected={mode === m} onClick={() => setMode(m)}
                  className={`h-8 rounded font-mono text-[12px] ${mode === m ? 'bg-surface-2 text-ink' : 'text-muted hover:text-ink'}`}>
                  {m === 'sms' ? 'SMS/WA' : m === 'raw' ? '.eml' : m.toUpperCase()}
                </button>
              ))}
            </div>
            {mode === 'url' ? (
              <label className="block"><span className="label">URL</span><input className="input mt-1 font-mono" value={f.url} onChange={set('url')} placeholder="https://…" autoFocus /></label>
            ) : mode === 'raw' ? (
              <label className="block"><span className="label">Raw RFC 822 message</span><textarea className="textarea mt-1 h-72" value={f.raw} onChange={set('raw')} placeholder="Paste the full source (Show original in Gmail)" /></label>
            ) : (
              <>
                {mode === 'email' && <label className="block"><span className="label">Subject</span><input className="input mt-1" value={f.subject} onChange={set('subject')} /></label>}
                <label className="block"><span className="label">{mode === 'sms' ? 'Sender number / ID' : 'From'}</span>
                  <input className="input mt-1 font-mono" value={f.sender} onChange={set('sender')} placeholder={mode === 'sms' ? '+91… or VM-SBIINB' : 'Name <address@domain>'} /></label>
                <label className="block"><span className="label">Message</span><textarea className="textarea mt-1 h-48 font-sans" value={f.body} onChange={set('body')} /></label>
              </>
            )}
            <label className="flex items-start gap-2 text-[13px]">
              <input type="checkbox" className="mt-1 accent-accent" checked={deep} onChange={(e) => setDeep(e.target.checked)} />
              <span>Full enrichment<span className="block text-[12px] text-muted">DNS, domain age, TLS, ASN and threat intel before answering (slower).</span></span>
            </label>
            <button className="btn btn-primary w-full" disabled={!canRun || busy}>{busy ? 'Analysing…' : 'Analyse'}</button>
          </form>
          <div className="mt-5 border-t border-line pt-4">
            <div className="label mb-2">Samples</div>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(SAMPLES).map(([name, s]) => (
                <button key={name} className="btn h-8 text-[12px]" onClick={() => { setMode(s.mode); setF({ subject: s.subject || '', sender: s.sender || '', body: s.body || '', url: s.url || '', raw: '' }); setRep(null); }}>{name}</button>
              ))}
            </div>
          </div>
        </Section>
        <div className="min-w-0">
          {err ? <ErrorBox error={err} /> : busy ? <Loading label="Running NLP, URL model, brand, intel and graph analysis" /> : rep ? <ReportView r={rep} /> : (
            <div className="card grid h-full min-h-72 place-items-center p-8 text-center text-[13px] text-muted">
              The verdict, every engine's score and the evidence behind it will appear here.
            </div>
          )}
        </div>
      </div>
    </>
  );
}
