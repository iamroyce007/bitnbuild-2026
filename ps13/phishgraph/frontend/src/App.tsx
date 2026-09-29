import { createContext, lazy, Suspense, useCallback, useContext, useEffect, useState } from 'react';
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { BrandLoader, PhishGraphWordmark } from './components/brand/PhishGraphLogo';
import CommandPalette from './components/CommandPalette';
import { Kbd, Toaster } from './components/kit';
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
const Landing = lazy(() => import('./pages/Landing'));
const Docs = lazy(() => import('./pages/Docs'));

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
  // "Live" only when the event stream is actually connected (skill rule: label telemetry live only when backed by a source)
  return (
    <span className="inline-flex items-center gap-2 font-mono text-[10.5px] uppercase tracking-[0.14em]" style={{ color: c }} role="status" aria-live="polite" title="Connection to the detection event stream">
      {state === 'live' ? <span className="status-dot" /> : <span className="size-1.5 rounded-full" style={{ background: c }} />}
      <span className="max-sm:hidden">{text}</span>
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
            <NavLink key={to} to={to} onClick={onPick} className={({ isActive }) => `group nav-item ${isActive ? 'nav-active' : ''}`}>
              {({ isActive }) => (<>
                <Icon name={icon} className={`size-4 shrink-0 transition-[transform,color] duration-200 ${isActive ? 'text-accent' : 'text-faint group-hover:translate-x-0.5 group-hover:text-ink'}`} />
                <span>{label}</span>
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
    <button onClick={onOpen} className="flex h-9 w-72 items-center gap-2 rounded-md border border-white/10 bg-white/5 px-3 text-left text-[13px] text-chrome-ink/60 transition-colors hover:border-white/30 hover:text-chrome-ink max-md:w-8 max-md:justify-center max-md:px-0" aria-label="Check a URL or jump to a page">
      <Icon name="search" className="size-4 shrink-0" />
      <span className="flex-1 truncate max-md:hidden">Check a URL, or jump to…</span>
      <span className="max-md:hidden"><Kbd>{mac ? '⌘' : 'Ctrl '}K</Kbd></span>
    </button>
  );
}

/** Shown only when this server was deployed as private and the browser has not been given access. */
function Private() {
  return (
    <div className="grid min-h-full place-items-center px-5">
      <div className="card max-w-md p-6">
        <div className="mb-3"><PhishGraphWordmark /></div>
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
  if (auth === 'checking') return <BrandLoader />;
  return <SampleCtx.Provider value={sampleCtx}><Root /></SampleCtx.Provider>;
}

/** The landing page stands alone (own navbar); everything else lives in the console shell. */
function Root() {
  const { pathname } = useLocation();
  if (pathname === '/') return <Suspense fallback={<BrandLoader label="Loading" />}><Landing /><Toaster /></Suspense>;
  return <Shell />;
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
  const [keys, setKeys] = useState(false);
  useEffect(() => setMenu(false), [pathname]);
  useEffect(() => {
    const on = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement)?.closest('input,textarea,select,[contenteditable]')) return;
      if (e.key === '?') { e.preventDefault(); setKeys((k) => !k); }
      if (e.key === 'Escape') setKeys(false);
    };
    window.addEventListener('keydown', on);
    return () => window.removeEventListener('keydown', on);
  }, []);
  const actions = [
    { id: 'a-inv', label: 'New investigation', hint: 'Action', icon: 'investigate', run: () => nav('/investigate') },
    { id: 'a-graph', label: 'Open threat graph', hint: 'Action', icon: 'graph', run: () => nav('/graph') },
    { id: 'a-intel', label: 'View threat intelligence', hint: 'Action', icon: 'intel', run: () => nav('/intel') },
    { id: 'a-docs', label: 'Documentation', hint: 'Action', icon: 'docs', run: () => nav('/documentation') },
    { id: 'a-keys', label: 'Keyboard shortcuts', hint: 'Action', icon: 'keyboard', run: () => setKeys(true) },
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
          <NavLink to="/" aria-label="PhishGraph home"><PhishGraphWordmark size={24} /></NavLink>
          <nav aria-label="Primary" className="ml-6 hidden items-center gap-0.5 xl:flex">
            {[['/investigate', 'Investigate'], ['/graph', 'Graph'], ['/intel', 'Intelligence'], ['/documentation', 'Documentation']].map(([to, l]) => (
              <NavLink key={to} to={to} className={({ isActive }) => `rounded-md px-3 py-1.5 text-[13px] transition-colors ${isActive ? 'bg-white/[0.07] text-chrome-ink' : 'text-chrome-ink/65 hover:bg-white/5 hover:text-chrome-ink'}`}>{l}</NavLink>
            ))}
          </nav>
          <div className="flex-1" />
          <PaletteButton onOpen={() => setPalette(true)} />
          <LinkBadge state={live.state} />
          <button className="grid size-8 place-items-center rounded hover:bg-chrome-2" onClick={toggleTheme}
            aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} title={theme === 'dark' ? 'Light theme' : 'Dark theme'}>
            <Icon name={theme === 'dark' ? 'sun' : 'moon'} />
          </button>
        </div></header>
        <div className="flex min-h-0 flex-1">
          <aside id="side-nav" className={`sidebar w-60 shrink-0 overflow-y-auto border-r border-line py-3 max-lg:fixed max-lg:inset-y-12 max-lg:bottom-14 max-lg:left-0 max-lg:z-30 max-lg:shadow-2xl ${menu ? 'drawer-in' : 'max-lg:hidden'}`}>
            <nav aria-label="Main"><NavItems /></nav>
          </aside>
          <div className="board flex min-w-0 flex-1 flex-col overflow-y-auto">
            <SampleBanner />
            <main id="main" className="safe-bottom w-full max-w-[1680px] flex-1 px-4 pb-20 pt-5 lg:px-6 lg:pb-6">
              <Suspense fallback={<Loading />}>
                <div key={pathname} className="page">
                <Routes>
                  <Route path="/overview" element={<Overview />} />
                  <Route path="/documentation" element={<Docs />} />
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
                  <Route path="*" element={<Navigate to="/overview" replace />} />
                </Routes>
                </div>
              </Suspense>
            </main>
          </div>
        </div>
      </div>
      {/* phones: bottom navigation, 5 destinations (skill: bottom nav <= 5) */}
      <nav aria-label="Quick" className="topbar safe-bottom fixed inset-x-0 bottom-0 z-40 grid h-14 grid-cols-5 lg:hidden">
        {([['/overview', 'home', 'Home'], ['/investigate', 'investigate', 'Investigate'], ['/analyze', 'analyze', 'Analyze'], ['/graph', 'graph', 'Graph']] as const).map(([to, icon, l]) => (
          <NavLink key={to} to={to} className={({ isActive }) => `flex flex-col items-center justify-center gap-0.5 text-[10.5px] ${isActive ? 'text-accent' : 'text-chrome-ink/65'}`}>
            <Icon name={icon} className="size-5" />{l}
          </NavLink>
        ))}
        <button onClick={() => setMenu((m) => !m)} aria-expanded={menu} aria-controls="side-nav" className={`flex flex-col items-center justify-center gap-0.5 text-[10.5px] ${menu ? 'text-accent' : 'text-chrome-ink/65'}`}>
          <Icon name="menu" className="size-5" />More
        </button>
      </nav>
      {keys && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/50 px-4 backdrop-blur-[2px]" onMouseDown={() => setKeys(false)}>
          <div role="dialog" aria-modal="true" aria-label="Keyboard shortcuts" className="pop card w-full max-w-sm p-5" onMouseDown={(e) => e.stopPropagation()}>
            <div className="mb-3 flex items-center justify-between"><h2 className="text-[15px] font-semibold">Keyboard shortcuts</h2><Kbd>esc</Kbd></div>
            <dl className="space-y-2 text-[13px]">
              {([['Command palette', '⌘K / Ctrl+K'], ['Focus investigation bar', '/'], ['This panel', '?'], ['Select graph entity', 'Enter'], ['Expand graph entity', 'E'], ['Clear input / close', 'Esc']] as const).map(([l, k]) => (
                <div key={l} className="flex items-center justify-between"><dt className="text-muted">{l}</dt><dd><Kbd>{k}</Kbd></dd></div>
              ))}
            </dl>
          </div>
        </div>
      )}
      <Toaster />
      <CommandPalette open={palette} setOpen={setPalette} actions={actions} />
    </LiveCtx.Provider>
  );
}
