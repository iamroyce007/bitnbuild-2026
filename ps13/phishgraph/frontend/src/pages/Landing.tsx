import { Activity, ArrowRight, BookOpen, Database, GitBranch, Globe, KeyRound, Network, Radar, ScanSearch, ShieldCheck, Sparkles, Target, Workflow } from 'lucide-react';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { PhishGraphMark, PhishGraphWordmark } from '../components/brand/PhishGraphLogo';
import HeroGraph from '../components/brand/HeroGraph';
import GraphView from '../components/GraphView';
import InvestigationInput from '../components/investigation/InvestigationInput';
import { StatusBadge } from '../components/kit';
import { CountUp } from '../components/ui';
import { api } from '../lib/api';
import { useApi } from '../lib/useApi';

const STEPS = [
  { icon: ScanSearch, t: 'Input', d: 'A domain, URL, IP, message or screenshot. Evasion tricks are undone first.' },
  { icon: Globe, t: 'Enrich', d: 'DNS, registration (RDAP), TLS certificate and network (ASN), behind an SSRF guard.' },
  { icon: Workflow, t: 'Correlate', d: 'Six engines score it; live feeds and look-alike analysis add hard evidence.' },
  { icon: Network, t: 'Graph', d: 'Entities join the infrastructure graph; shared IPs, certificates and nameservers link campaigns.' },
  { icon: Radar, t: 'Investigate', d: 'An explainable verdict with the exact evidence path an analyst can verify.' },
];
const FEATURES = [
  { icon: GitBranch, t: 'Graph intelligence', d: 'Every message, link, domain, IP, certificate and nameserver becomes a node. Hub-dampened scoring means a shared CDN never links two sites; an uncommon nameserver does.' },
  { icon: Target, t: 'Infrastructure correlation', d: 'A domain nobody has listed yet is caught when it shares infrastructure with one that is: the path is shown, hop by hop.' },
  { icon: ShieldCheck, t: 'Threat detection', d: 'Language, URL structure, brand look-alikes (UTS #39 confusables, 95 brands, Tranco top 10k), sender checks, live intelligence and graph risk, fused with a corroboration rule.' },
  { icon: Sparkles, t: 'Campaign discovery', d: 'Messages cluster into campaigns by meaning, shared infrastructure, brand and time, so one takedown covers the whole operation.' },
];
const SOURCES = {
  live: ['OpenPhish', 'URLhaus', 'CERT Polska', 'Phishing Army'],
  enrich: ['DNS (A, NS, MX)', 'RDAP registration', 'TLS certificate', 'Team Cymru IP→ASN', 'Tranco ranking', 'Public Suffix List'],
  keyed: ['VirusTotal', 'urlscan.io', 'Google Safe Browsing', 'AlienVault OTX', 'AbuseIPDB', 'PhishTank'],
};

function Nav() {
  return (
    <header className="topbar sticky top-0 z-40">
      <div className="mx-auto flex h-14 max-w-[1240px] items-center gap-6 px-5">
        <Link to="/" aria-label="PhishGraph home"><PhishGraphWordmark /></Link>
        <nav aria-label="Primary" className="hidden flex-1 justify-center gap-1 md:flex">
          {[['/investigate', 'Investigate'], ['/graph', 'Graph'], ['/intel', 'Intelligence'], ['/documentation', 'Documentation']].map(([to, l]) => (
            <Link key={to} to={to} className="rounded-md px-3 py-1.5 text-[13px] text-chrome-ink/70 transition-colors hover:bg-white/5 hover:text-chrome-ink">{l}</Link>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-2 md:ml-0">
          <Link to="/overview" className="btn h-8 text-[12.5px]">Open console</Link>
        </div>
      </div>
    </header>
  );
}

export default function Landing() {
  const nav = useNavigate();
  const [q, setQ] = useState('');
  const stats = useApi(() => api.statistics(24));
  const graph = useApi(() => api.graphOverview());
  const s = stats.data;
  return (
    <div className="min-h-full">
      <Nav />
      <main id="main">
        {/* HERO */}
        <section className="relative overflow-hidden border-b border-line">
          <HeroGraph className="absolute inset-0 h-full w-full opacity-70" />
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(60%_60%_at_50%_40%,transparent,var(--color-bg)_85%)]" aria-hidden="true" />
          <div className="relative mx-auto max-w-[1240px] px-5 pb-20 pt-20 sm:pt-28">
            <div className="page mx-auto max-w-3xl text-center">
              <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-line-strong bg-surface/70 px-3 py-1 backdrop-blur">
                <StatusBadge label="Live phishing intelligence" tone="accent" live />
              </div>
              <h1 className="text-[40px] font-semibold leading-[1.05] tracking-[-0.035em] sm:text-[60px]">
                Map the infrastructure<br className="hidden sm:block" /> behind the <span className="hl">phish</span>.
              </h1>
              <p className="mx-auto mt-5 max-w-2xl text-[16px] leading-relaxed text-muted sm:text-[17px]">
                PhishGraph connects domains, URLs, IPs, certificates and nameservers to known-bad infrastructure, so a phishing site nobody has reported yet is exposed by what it shares, with every step of the evidence shown.
              </p>
              <div className="mx-auto mt-9 max-w-2xl text-left">
                <InvestigationInput value={q} onChange={setQ} size="lg" onSubmit={(v) => nav(`/investigate?url=${encodeURIComponent(v)}`)} />
              </div>
            </div>
            <p className="mt-10 text-center font-mono text-[10px] uppercase tracking-[0.2em] text-faint">Background: illustration, not live data</p>
          </div>
        </section>

        {/* LIVE METRICS (real, from this deployment) */}
        <section className="border-b border-line bg-surface/30">
          <div className="mx-auto grid max-w-[1240px] grid-cols-2 gap-px px-5 py-8 md:grid-cols-4">
            {[
              ['Threat indicators', s?.threat_feed_size, Database],
              ['Graph entities', s?.graph.nodes, Network],
              ['Messages & links analysed', s?.total_detections, Activity],
              ['Campaigns', s?.campaigns, Target],
            ].map(([label, v, I]) => {
              const Icon = I as typeof Activity;
              return (
                <div key={label as string} className="px-4 py-2">
                  <div className="flex items-center gap-2 font-mono text-[10.5px] uppercase tracking-[0.16em] text-faint"><Icon className="size-3.5" />{label as string}</div>
                  <div className="kpi-num mt-2 text-[32px] font-semibold leading-none tracking-tight">{typeof v === 'number' ? <CountUp value={v} /> : <span className="skeleton inline-block h-8 w-24 align-middle" />}</div>
                </div>
              );
            })}
          </div>
          <p className="mx-auto max-w-[1240px] px-9 pb-5 text-[11.5px] text-faint">Live from this deployment. Indicators come from the keyless public feeds listed below.</p>
        </section>

        {/* HOW IT WORKS */}
        <section className="mx-auto max-w-[1240px] px-5 py-20">
          <div className="eyebrow">How it works</div>
          <h2 className="mt-2 max-w-2xl text-[30px] font-semibold leading-tight tracking-[-0.02em] sm:text-[36px]">From one suspicious link to the campaign behind it.</h2>
          <ol className="stagger mt-10 grid gap-3 md:grid-cols-5">
            {STEPS.map(({ icon: I, t, d }, i) => (
              <li key={t} className="card card-hover relative p-5">
                <div className="flex items-center justify-between">
                  <span className="grid size-9 place-items-center rounded-md border border-line-strong bg-surface-2"><I className="size-4 text-accent" strokeWidth={1.75} /></span>
                  <span className="font-mono text-[11px] text-faint">0{i + 1}</span>
                </div>
                <div className="mt-4 text-[15px] font-semibold">{t}</div>
                <p className="mt-1.5 text-[13px] leading-relaxed text-muted">{d}</p>
                {i < STEPS.length - 1 && <ArrowRight className="absolute -right-2.5 top-1/2 z-10 hidden size-4 -translate-y-1/2 text-faint md:block" aria-hidden="true" />}
              </li>
            ))}
          </ol>
        </section>

        {/* LIVE INFRASTRUCTURE (real data) */}
        <section className="border-y border-line bg-surface/30">
          <div className="mx-auto grid max-w-[1240px] gap-10 px-5 py-20 lg:grid-cols-[360px_minmax(0,1fr)]">
            <div>
              <div className="eyebrow">Live investigation view</div>
              <h2 className="mt-2 text-[30px] font-semibold leading-tight tracking-[-0.02em]">Today's phishing infrastructure, mapped.</h2>
              <p className="mt-4 text-[14px] leading-relaxed text-muted">Real data from this deployment: live phishing from OpenPhish and URLhaus, grouped by the brand each site impersonates and the hosting platform it abuses, alongside analysed messages and their campaigns.</p>
              <ul className="mt-5 space-y-2 text-[13px] text-muted">
                <li className="flex gap-2"><span className="mt-1.5 size-2 shrink-0 rounded-full border-2 border-block" />Known-malicious entities pulse</li>
                <li className="flex gap-2"><span className="mt-1.5 size-2 shrink-0 rounded-full border-2 border-accent" />Brands and official sites</li>
                <li className="flex gap-2"><span className="mt-1.5 size-2 shrink-0 rounded-full bg-accent" />Packets trace relationships that touch a threat</li>
              </ul>
              <Link to="/graph" className="btn mt-6">Explore the graph <ArrowRight className="size-4" /></Link>
            </div>
            <div className="min-w-0">
              {graph.data ? <GraphView data={graph.data} height={440} /> : <div className="skeleton h-[440px] rounded-md" />}
            </div>
          </div>
        </section>

        {/* FEATURES */}
        <section className="mx-auto max-w-[1240px] px-5 py-20">
          <div className="eyebrow">Capabilities</div>
          <div className="mt-8 grid gap-3 md:grid-cols-2">
            {FEATURES.map(({ icon: I, t, d }) => (
              <div key={t} className="card card-hover p-6">
                <I className="size-5 text-accent" strokeWidth={1.75} />
                <h3 className="mt-4 text-[17px] font-semibold tracking-tight">{t}</h3>
                <p className="mt-2 text-[13.5px] leading-relaxed text-muted">{d}</p>
              </div>
            ))}
          </div>
        </section>

        {/* SOURCES (real integrations only) */}
        <section className="border-y border-line bg-surface/30">
          <div className="mx-auto max-w-[1240px] px-5 py-20">
            <div className="eyebrow">Intelligence sources</div>
            <h2 className="mt-2 text-[30px] font-semibold tracking-[-0.02em]">What PhishGraph actually consults.</h2>
            <div className="mt-8 grid gap-3 md:grid-cols-3">
              {([['Live feeds · always on, no key', SOURCES.live, Radar], ['Enrichment · built in', SOURCES.enrich, Globe], ['With your API key', SOURCES.keyed, KeyRound]] as const).map(([h, list, I]) => (
                <div key={h} className="card p-5">
                  <div className="flex items-center gap-2 font-mono text-[10.5px] uppercase tracking-[0.16em] text-faint"><I className="size-3.5" />{h}</div>
                  <ul className="mt-4 space-y-2">{list.map((x) => <li key={x} className="flex items-center gap-2 text-[13.5px]"><span className="size-1 rounded-full bg-accent" />{x}</li>)}</ul>
                </div>
              ))}
            </div>
            <p className="mt-4 text-[12px] text-faint">Keyed providers report "not configured" until a key is added. A missing source is never treated as "clean".</p>
          </div>
        </section>

        {/* CTA */}
        <section className="mx-auto max-w-[1240px] px-5 py-24 text-center">
          <PhishGraphMark size={48} className="mx-auto" />
          <h2 className="mx-auto mt-6 max-w-xl text-[32px] font-semibold leading-tight tracking-[-0.025em]">Something look off? Check it before anyone clicks.</h2>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <Link to="/investigate" className="btn btn-primary h-11 px-5 font-mono text-[12.5px] tracking-[0.1em]">START INVESTIGATION <ArrowRight className="size-4" /></Link>
            <Link to="/analyze" className="btn h-11 px-5">Check a message or screenshot</Link>
          </div>
        </section>
      </main>
      <footer className="border-t border-line">
        <div className="mx-auto flex max-w-[1240px] flex-wrap items-center justify-between gap-3 px-5 py-6 text-[12px] text-faint">
          <span className="flex items-center gap-2"><PhishGraphMark size={18} />PhishGraph · Bit N Build 2026 · PSN013</span>
          <span className="flex gap-4"><Link to="/validation" className="hover:text-ink">Training & validation</Link><Link to="/documentation" className="inline-flex items-center gap-1 hover:text-ink"><BookOpen className="size-3.5" />Documentation</Link></span>
        </div>
      </footer>
    </div>
  );
}
