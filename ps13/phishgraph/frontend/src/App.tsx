import { createContext, lazy, Suspense, useCallback, useContext, useEffect, useState } from 'react';
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { Icon, Loading, NAV_GROUPS } from './components/ui';
import { api } from './lib/api';
import { type LinkState, useEvents } from './lib/events';
import type { LiveEvent } from './lib/types';

// every page is its own chunk: first load ships only the shell + the page you open
const Overview = lazy(() => import('./pages/Overview'));
const Feed = lazy(() => import('./pages/Feed'));
const Analyze = lazy(() => import('./pages/Analyze'));
const Investigate = lazy(() => import('./pages/Investigate'));
const Detection = lazy(() => import('./pages/Detection'));
const Graph = lazy(() => import('./pages/Graph'));
const Campaigns = lazy(() => import('./pages/Campaigns'));
const Campaign = lazy(() => import('./pages/Campaign'));
const Intel = lazy(() => import('./pages/Intel'));
const Models = lazy(() => import('./pages/Models'));
const Review = lazy(() => import('./pages/Review'));
const Health = lazy(() => import('./pages/Health'));
const Settings = lazy(() => import('./pages/Settings'));
const Setup = lazy(() => import('./pages/Setup'));

type Live = { state: LinkState; events: LiveEvent[]; paused: boolean; setPaused: (p: boolean) => void };
const LiveCtx = createContext<Live>({ state: 'offline', events: [], paused: false, setPaused: () => {} });
export const useLive = () => useContext(LiveCtx);

type Sample = { loaded: boolean; count: number; busy: boolean; load: () => void; clear: () => void };
const SampleCtx = createContext<Sample>({ loaded: false, count: 0, busy: false, load: () => {}, clear: () => {} });
export const useSample = () => useContext(SampleCtx);

type Theme = 'light' | 'dark' | 'system';
const THEME_KEY = 'phishgraph.theme';
function applyTheme(t: Theme) {
  if (t === 'system') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = t;
}
function useTheme(): [Theme, () => void] {
  const [t, setT] = useState<Theme>(() => (localStorage.getItem(THEME_KEY) as Theme) || 'light');
  useEffect(() => { applyTheme(t); localStorage.setItem(THEME_KEY, t); }, [t]);
  return [t, () => setT((x) => (x === 'dark' ? 'light' : 'dark'))];
}

function LinkBadge({ state }: { state: LinkState }) {
  const c = state === 'live' ? 'var(--color-allow)' : state === 'polling' ? 'var(--color-flag)' : 'var(--color-neutral)';
  const text = state === 'live' ? 'Live' : state === 'polling' ? 'Polling' : 'Offline';
  return (
    <span className="inline-flex items-center gap-1.5 text-[12px]" role="status" aria-live="polite" title="Connection to the detection event stream">
      <span className="size-2 rounded-full" style={{ background: c }} />
      {text}
    </span>
  );
}

function NavItems({ onPick }: { onPick?: () => void }) {
  return (
    <>
      {NAV_GROUPS.map((g) => (
        <div key={g.group} className="mb-3">
          <div className="px-3 pb-1 pt-2 text-[11px] font-semibold uppercase tracking-wider text-faint">{g.group}</div>
          {g.items.map(([to, icon, label]) => (
            <NavLink key={to} to={to} end={to === '/'} onClick={onPick}
              className={({ isActive }) => `flex items-center gap-2.5 border-l-[3px] px-3 py-1.5 text-[13px] ${isActive ? 'border-accent bg-surface-2 font-semibold text-ink' : 'border-transparent text-muted hover:bg-surface-2 hover:text-ink'}`}>
              <Icon name={icon} />{label}
            </NavLink>
          ))}
        </div>
      ))}
    </>
  );
}

function SampleBanner() {
  const s = useSample();
  if (!s.loaded) return null;
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-flag/40 bg-flag/5 px-5 py-1.5 text-[13px]" role="status">
      <span><span className="font-semibold text-flag">Sample data loaded.</span> <span className="text-muted">{s.count} example messages and fictional infrastructure, each marked DEMO DATA.</span></span>
      <button className="btn h-7 text-[12px]" onClick={s.clear} disabled={s.busy}>{s.busy ? 'Removing…' : 'Remove sample data'}</button>
    </div>
  );
}

/** Top-bar lookup: opens a full investigation of a URL or domain. */
function QuickLookup() {
  const nav = useNavigate();
  const [q, setQ] = useState('');
  const go = (e: React.FormEvent) => {
    e.preventDefault();
    const v = q.trim();
    if (!v) return;
    nav(`/investigate?url=${encodeURIComponent(v)}`);
    setQ('');
  };
  return (
    <form onSubmit={go} role="search" className="relative max-md:hidden">
      <Icon name="search" className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-chrome-ink/60" />
      <label htmlFor="lookup" className="sr-only">Check a URL or domain</label>
      <input id="lookup" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Check a URL or domain"
        className="h-8 w-72 rounded border border-white/15 bg-chrome-2 pl-8 pr-2 text-[13px] text-chrome-ink placeholder:text-chrome-ink/55 focus:border-accent focus:outline-none" />
    </form>
  );
}

/** Shown only when this server was deployed as private and the browser has not been given access. */
function Private() {
  return (
    <div className="grid min-h-full place-items-center px-5">
      <div className="card max-w-md p-6">
        <div className="mb-3 flex items-center gap-2.5"><img src="/favicon.svg" alt="" width={24} height={24} /><span className="font-semibold">PhishGraph</span></div>
        <h1 className="text-[17px] font-semibold">This server is private</h1>
        <p className="mt-1 text-[13px] text-muted">Open the setup link from the person who runs it. The public server at phishgraph.vercel.app needs no access.</p>
      </div>
    </div>
  );
}

export default function App() {
  const [auth, setAuth] = useState<'checking' | 'ok' | 'needed'>('checking');
  const [sample, setSample] = useState({ loaded: false, count: 0, busy: false });
  const refreshSample = useCallback(async () => {
    try {
      const st = await api.sampleStatus();
      setSample((x) => ({ ...x, loaded: st.loaded, count: st.sample_detections }));
      setAuth('ok');
    } catch (e) {
      setAuth(e instanceof Error && /401|key/i.test(e.message) ? 'needed' : 'ok');
    }
  }, []);
  useEffect(() => { if (auth === 'checking') refreshSample(); }, [auth, refreshSample]);
  const sampleCtx: Sample = {
    ...sample,
    load: async () => { setSample((x) => ({ ...x, busy: true })); try { await api.loadSample(); } finally { await refreshSample(); setSample((x) => ({ ...x, busy: false })); window.dispatchEvent(new Event('phishgraph:data-changed')); } },
    clear: async () => { setSample((x) => ({ ...x, busy: true })); try { await api.clearSample(); } finally { await refreshSample(); setSample((x) => ({ ...x, busy: false })); window.dispatchEvent(new Event('phishgraph:data-changed')); } },
  };
  if (auth === 'needed') return <Private />;
  if (auth === 'checking') return <Loading label="Connecting" />;
  return <SampleCtx.Provider value={sampleCtx}><Shell /></SampleCtx.Provider>;
}

function Shell() {
  const [paused, setPaused] = useState(false);
  const live = useEvents();
  const [menu, setMenu] = useState(false);
  const [theme, toggleTheme] = useTheme();
  const { pathname } = useLocation();
  useEffect(() => setMenu(false), [pathname]);
  return (
    <LiveCtx.Provider value={{ ...live, paused, setPaused }}>
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-accent focus:px-3 focus:py-2 focus:text-on-accent">Skip to content</a>
      <div className="flex h-full flex-col">
        <header className="sticky top-0 z-30 flex h-12 shrink-0 items-center gap-3 bg-chrome px-3 text-chrome-ink lg:px-4">
          <button className="grid size-8 place-items-center rounded hover:bg-chrome-2 lg:hidden" onClick={() => setMenu((m) => !m)} aria-expanded={menu} aria-controls="side-nav" aria-label="Menu">
            <Icon name="menu" className="size-5" />
          </button>
          <NavLink to="/" className="flex items-center gap-2.5">
            <img src="/favicon.svg" alt="" width={22} height={22} />
            <span className="text-[15px] font-semibold">PhishGraph</span>
          </NavLink>
          <span className="hidden h-5 w-px bg-white/20 sm:block" aria-hidden="true" />
          <span className="hidden text-[13px] text-chrome-ink/75 sm:block">Phishing Defense Console</span>
          <div className="flex-1" />
          <QuickLookup />
          <LinkBadge state={live.state} />
          <button className="grid size-8 place-items-center rounded hover:bg-chrome-2" onClick={toggleTheme}
            aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} title={theme === 'dark' ? 'Light theme' : 'Dark theme'}>
            <Icon name={theme === 'dark' ? 'sun' : 'moon'} />
          </button>
        </header>
        <div className="flex min-h-0 flex-1">
          <aside id="side-nav" className={`w-56 shrink-0 overflow-y-auto border-r border-line bg-surface py-2 max-lg:fixed max-lg:inset-y-12 max-lg:left-0 max-lg:z-20 max-lg:shadow-lg ${menu ? '' : 'max-lg:hidden'}`}>
            <nav aria-label="Main"><NavItems /></nav>
          </aside>
          <div className="flex min-w-0 flex-1 flex-col overflow-y-auto">
            <SampleBanner />
            <main id="main" className="w-full max-w-[1600px] flex-1 px-4 py-5 lg:px-6">
              <Suspense fallback={<Loading />}>
                <Routes>
                  <Route path="/" element={<Overview />} />
                  <Route path="/feed" element={<Feed />} />
                  <Route path="/analyze" element={<Analyze />} />
                  <Route path="/investigate" element={<Investigate />} />
                  <Route path="/detections/:id" element={<Detection />} />
                  <Route path="/graph" element={<Graph />} />
                  <Route path="/campaigns" element={<Campaigns />} />
                  <Route path="/campaigns/:id" element={<Campaign />} />
                  <Route path="/review" element={<Review />} />
                  <Route path="/intel" element={<Intel />} />
                  <Route path="/models" element={<Models />} />
                  <Route path="/health" element={<Health />} />
                  <Route path="/settings" element={<Settings />} />
                  <Route path="/setup" element={<Setup />} />
                  <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
              </Suspense>
            </main>
          </div>
        </div>
      </div>
    </LiveCtx.Provider>
  );
}
