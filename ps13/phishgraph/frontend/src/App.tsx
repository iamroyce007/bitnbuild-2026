import { createContext, lazy, Suspense, useCallback, useContext, useEffect, useState } from 'react';
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import CommandPalette from './components/CommandPalette';
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
const Validation = lazy(() => import('./pages/Validation'));

type Live = { state: LinkState; events: LiveEvent[]; paused: boolean; setPaused: (p: boolean) => void };
const LiveCtx = createContext<Live>({ state: 'offline', events: [], paused: false, setPaused: () => {} });
export const useLive = () => useContext(LiveCtx);

type Sample = { loaded: boolean; count: number; busy: boolean; load: () => void; clear: () => void };
const SampleCtx = createContext<Sample>({ loaded: false, count: 0, busy: false, load: () => {}, clear: () => {} });
export const useSample = () => useContext(SampleCtx);

type Theme = 'light' | 'dark' | 'system';
const THEME_KEY = 'phishgraph.ui-theme'; // renamed when dark became the default, so old saved choices do not pin light
function applyTheme(t: Theme) {
  if (t === 'system') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = t;
}
function useTheme(): [Theme, () => void] {
  const [t, setT] = useState<Theme>(() => (localStorage.getItem(THEME_KEY) as Theme) || 'dark');
  useEffect(() => { applyTheme(t); localStorage.setItem(THEME_KEY, t); }, [t]);
  return [t, () => setT((x) => (x === 'dark' ? 'light' : 'dark'))];
}

function LinkBadge({ state }: { state: LinkState }) {
  const c = state === 'live' ? 'var(--color-allow)' : state === 'polling' ? 'var(--color-flag)' : 'var(--color-neutral)';
  const text = state === 'live' ? 'Live' : state === 'polling' ? 'Polling' : 'Offline';
  return (
    <span className="inline-flex items-center gap-1.5 text-[12px]" role="status" aria-live="polite" title="Connection to the detection event stream">
      <span className={`size-2 rounded-full ${state === 'live' ? 'live-dot' : ''}`} style={{ background: c, color: c }} />
      {text}
    </span>
  );
}

function NavItems({ onPick }: { onPick?: () => void }) {
  return (
    <>
      {NAV_GROUPS.map((g) => (
        <div key={g.group} className="mb-3">
          <div className="eyebrow px-5 pb-1.5 pt-3">{g.group}</div>
          {g.items.map(([to, icon, label]) => (
            <NavLink key={to} to={to} end={to === '/'} onClick={onPick}
              className={({ isActive }) => `group nav-item ${isActive ? 'nav-active' : ''}`}>
              {({ isActive }) => (<>
                <Icon name={icon} className={`size-4 transition-transform duration-200 ${isActive ? '' : 'group-hover:translate-x-0.5'}`} />
                <span className={isActive ? 'hl' : ''}>{label}</span>
              </>)}
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

function PaletteButton({ onOpen }: { onOpen: () => void }) {
  const mac = /Mac|iPhone|iPad/.test(navigator.platform);
  return (
    <button onClick={onOpen} className="flex h-9 w-80 items-center gap-2 rounded-lg border border-white/10 bg-white/5 px-3 text-left text-[13px] text-chrome-ink/60 transition-colors hover:border-white/30 hover:text-chrome-ink max-md:w-8 max-md:justify-center max-md:px-0" aria-label="Check a URL or jump to a page">
      <Icon name="search" className="size-4 shrink-0" />
      <span className="flex-1 truncate max-md:hidden">Check a URL, or jump to…</span>
      <kbd className="font-mono text-[11px] max-md:hidden">{mac ? '⌘' : 'Ctrl '}K</kbd>
    </button>
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
  const nav = useNavigate();
  const [palette, setPalette] = useState(false);
  const sample = useSample();
  useEffect(() => setMenu(false), [pathname]);
  const actions = [
    { id: 'a-shot', label: 'Analyse a screenshot', hint: 'Action', icon: 'analyze', run: () => nav('/analyze') },
    { id: 'a-theme', label: `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`, hint: 'Action', icon: theme === 'dark' ? 'sun' : 'moon', run: toggleTheme },
    ...(sample.loaded ? [] : [{ id: 'a-sample', label: 'Load sample data', hint: 'Action', icon: 'campaigns', run: sample.load }]),
  ];
  return (
    <LiveCtx.Provider value={{ ...live, paused, setPaused }}>
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-accent focus:px-3 focus:py-2 focus:text-on-accent">Skip to content</a>
      <div className="flex h-full flex-col">
        <header className="topbar safe-top sticky top-0 z-30 shrink-0 text-chrome-ink"><div className="safe-x flex h-12 items-center gap-3 lg:px-4">
          <button className="grid size-8 place-items-center rounded hover:bg-chrome-2 lg:hidden" onClick={() => setMenu((m) => !m)} aria-expanded={menu} aria-controls="side-nav" aria-label="Menu">
            <Icon name="menu" className="size-5" />
          </button>
          <NavLink to="/" className="flex items-center gap-2.5">
            <img src="/favicon.svg" alt="" width={24} height={24} />
            <span className="text-[16px] font-semibold tracking-tight">Phish<span className="hl font-semibold">Graph</span></span>
          </NavLink>
          <span className="hidden items-center gap-2 font-mono text-[10.5px] tracking-[0.14em] text-chrome-ink/60 uppercase sm:flex">/ threat defense platform <span className="rounded-full border border-accent/40 bg-accent/10 px-2 py-px text-[9.5px] tracking-[0.12em] text-accent">enterprise</span></span>
          <div className="flex-1" />
          <PaletteButton onOpen={() => setPalette(true)} />
          <LinkBadge state={live.state} />
          <button className="grid size-8 place-items-center rounded hover:bg-chrome-2" onClick={toggleTheme}
            aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} title={theme === 'dark' ? 'Light theme' : 'Dark theme'}>
            <Icon name={theme === 'dark' ? 'sun' : 'moon'} />
          </button>
        </div></header>
        <div className="flex min-h-0 flex-1">
          <aside id="side-nav" className={`sidebar w-60 shrink-0 overflow-y-auto border-r border-line py-3 max-lg:fixed max-lg:inset-y-12 max-lg:left-0 max-lg:z-20 max-lg:shadow-lg ${menu ? '' : 'max-lg:hidden'}`}>
            <nav aria-label="Main"><NavItems /></nav>
          </aside>
          <div className="board flex min-w-0 flex-1 flex-col overflow-y-auto">
            <SampleBanner />
            <main id="main" className="safe-bottom w-full max-w-[1600px] flex-1 px-4 py-5 lg:px-6">
              <Suspense fallback={<Loading />}>
                <div key={pathname} className="page">
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
                  <Route path="/system" element={<Health />} />
                  <Route path="/validation" element={<Validation />} />
                  <Route path="/settings" element={<Settings />} />
                  <Route path="/setup" element={<Setup />} />
                  <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
                </div>
              </Suspense>
            </main>
          </div>
        </div>
      </div>
      <CommandPalette open={palette} setOpen={setPalette} actions={actions} />
    </LiveCtx.Provider>
  );
}
