import { BookOpen, Keyboard, Server, ShieldCheck } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Kbd } from '../components/kit';
import { PageTitle, Section } from '../components/ui';

const ENGINES: [string, string][] = [
  ['Language (NLP)', 'TF-IDF and MiniLM models plus 20 scam intents in English, Hindi, Tamil, Hinglish and Tanglish.'],
  ['URL structure', 'Character n-grams and 37 lexical features on the canonical URL, calibrated; never decides alone.'],
  ['Brand look-alikes', '95 curated brands + Tranco top 10k; homographs, digit swaps, typos, permutations, combos, subdomain tricks.'],
  ['Sender & headers', 'SPF/DKIM/DMARC, display-name spoofing, reply-to mismatch, Indian DLT SMS headers.'],
  ['Threat intelligence', '~150k live indicators (OpenPhish, URLhaus, CERT Polska, Phishing Army) + keyed providers.'],
  ['Infrastructure graph', 'Shared IPs, certificates, nameservers, hosting platforms and campaigns, hub-dampened.'],
];
const API: [string, string][] = [
  ['POST /api/v1/analyze/email', 'Email, SMS or WhatsApp text (or raw RFC 822)'],
  ['POST /api/v1/analyze/url', 'One URL, fast path'],
  ['POST /api/v1/investigate', 'Full chain for an unknown URL; poll /jobs/{id}'],
  ['POST /api/v1/extract', 'Structure OCR text from a screenshot'],
  ['GET /api/v1/graph/overview · /graph/domain/{d} · /graph/detection/{id}', 'Graph JSON'],
  ['GET /api/v1/validation', 'Model versions and every recorded test run'],
];

export default function Docs() {
  return (
    <>
      <PageTitle title="Documentation" sub="How PhishGraph reaches a verdict, what it guarantees, and how to use it." />
      <div className="grid grid-cols-[minmax(0,1fr)] gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
        <div className="space-y-5">
          <Section title="How a verdict is made" right={<BookOpen className="size-4 text-faint" />}>
            <ol className="discover space-y-3 text-[13.5px]">
              <li><b>1. Normalise.</b> <span className="text-muted">Zero-width characters, look-alike letters, defanged links (hxxp, [.]) and hidden links are undone; each trick counts as evidence.</span></li>
              <li><b>2. Score in parallel.</b> <span className="text-muted">Six independent engines (below).</span></li>
              <li><b>3. Fuse.</b> <span className="text-muted">Weights are renormalised over sources that answered (missing is never "safe"). Hard evidence sets floors; QUARANTINE/BLOCK needs two independent evidence families; a verified sender lowers risk.</span></li>
              <li><b>4. Explain.</b> <span className="text-muted">Every reason is copied from the engine that produced it, with its weight. No text generator writes explanations.</span></li>
              <li><b>5. Learn.</b> <span className="text-muted">Analyst confirmations update the feed and graph and join the next training run.</span></li>
            </ol>
            <div className="mt-5 grid gap-2 sm:grid-cols-2">
              {ENGINES.map(([t, d]) => <div key={t} className="rounded-md border border-line bg-surface-2/40 p-3"><div className="text-[13px] font-semibold">{t}</div><p className="mt-1 text-[12.5px] text-muted">{d}</p></div>)}
            </div>
          </Section>
          <Section title="The brand guarantee" right={<ShieldCheck className="size-4 text-faint" />}>
            <p className="text-[13.5px] leading-relaxed">A message that presents itself as a protected brand, is not from that brand's verified sender, and links anywhere outside its official domains is <b>never allowed</b>. It is at least flagged, and the report says to use the official site instead.</p>
            <p className="mt-2 text-[12.5px] text-muted">Proven for all 95 protected brands by an exhaustive test. It covers brand impersonation with a link; messages without a link or a brand claim rely on the scored engines. User-content hosts (sites.google.com, *.github.io, *.weebly.com) never count as official.</p>
          </Section>
          <Section title="API" right={<Server className="size-4 text-faint" />} flush>
            <table className="tbl"><tbody>{API.map(([e, d]) => <tr key={e}><td className="font-mono text-[12px]">{e}</td><td className="text-[12.5px] text-muted">{d}</td></tr>)}</tbody></table>
          </Section>
        </div>
        <div className="space-y-5">
          <Section title="Keyboard shortcuts" right={<Keyboard className="size-4 text-faint" />}>
            <dl className="space-y-2 text-[13px]">
              {([['Command palette', ['⌘', 'K']], ['Focus investigation bar', ['/']], ['Keyboard shortcuts', ['?']], ['Clear input', ['Esc']], ['Select graph entity', ['Enter']], ['Expand graph entity', ['E']]] as const).map(([l, k]) => (
                <div key={l} className="flex items-center justify-between"><dt className="text-muted">{l}</dt><dd className="flex gap-1">{k.map((x) => <Kbd key={x}>{x}</Kbd>)}</dd></div>
              ))}
            </dl>
          </Section>
          <Section title="Honest limits">
            <ul className="list-disc space-y-1.5 pl-5 text-[12.5px] text-muted">
              <li>From a URL alone, engines flag about 4 in 10 never-seen phishing URLs; live feeds and full enrichment catch far more. See <Link to="/validation" className="text-accent hover:underline">Training & validation</Link>.</li>
              <li>External providers need your API keys; until then they say "not configured".</li>
              <li>Automated response is simulated unless mailbox access is configured. Nothing is ever deleted.</li>
            </ul>
          </Section>
        </div>
      </div>
    </>
  );
}
