import { createContext, lazy, Suspense, useContext, useState } from 'react';
import { NavLink, Navigate, Route, Routes } from 'react-router-dom';
import { Icon, Loading } from './components/ui';
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

type Live = { state: LinkState; events: LiveEvent[]; paused: boolean; setPaused: (p: boolean) => void };
const LiveCtx = createContext<Live>({ state: 'offline', events: [], paused: false, setPaused: () => {} });
export const useLive = () => useContext(LiveCtx);

const NAV: [string, string, string][] = [
  ['/', 'overview', 'Overview'],
  ['/feed', 'feed', 'Live detections'],
  ['/analyze', 'analyze', 'Analyze message'],
  ['/investigate', 'investigate', 'Investigate URL'],
  ['/graph', 'graph', 'Threat graph'],
  ['/campaigns', 'campaigns', 'Campaigns'],
  ['/review', 'review', 'Review queue'],
  ['/intel', 'intel', 'Threat intelligence'],
  ['/models', 'models', 'Model health'],
  ['/health', 'health', 'System health'],
];

function LinkBadge({ state }: { state: LinkState }) {
  const c = state === 'live' ? '#2fbf71' : state === 'polling' ? '#e0a106' : '#66717e';
  const text = state === 'live' ? 'Live' : state === 'polling' ? 'Polling' : 'Offline';
  return (
    <span className="inline-flex items-center gap-2 font-mono text-[12px]" style={{ color: c }} role="status" aria-live="polite">
      <span className="size-2 rounded-full" style={{ background: c }} />
      {text}
    </span>
  );
}

function NavItems({ onPick }: { onPick?: () => void }) {
  return (
    <>
      {NAV.map(([to, icon, label]) => (
        <NavLink key={to} to={to} end={to === '/'} onClick={onPick}
          className={({ isActive }) => `flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] transition-colors duration-150 ${isActive ? 'bg-surface-2 text-ink' : 'text-muted hover:bg-surface hover:text-ink'}`}>
          <Icon name={icon} />{label}
        </NavLink>
      ))}
    </>
  );
}

export default function App() {
  const [paused, setPaused] = useState(false);
  const live = useEvents();
  const [menu, setMenu] = useState(false);
  return (
    <LiveCtx.Provider value={{ ...live, paused, setPaused }}>
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-accent focus:px-3 focus:py-2 focus:text-black">Skip to content</a>
      <div className="grid h-full grid-cols-[220px_1fr] max-lg:grid-cols-1">
        <aside className="flex flex-col border-r border-line bg-[#0a0d11] max-lg:hidden">
          <div className="flex items-center gap-2.5 px-5 py-5">
            <img src="/favicon.svg" alt="" width={26} height={26} />
            <div className="text-[15px] font-semibold tracking-tight">PhishGraph</div>
          </div>
          <nav className="flex-1 space-y-0.5 px-2.5" aria-label="Main"><NavItems /></nav>
          <div className="border-t border-line px-2.5 py-3">
            <NavLink to="/settings" className={({ isActive }) => `flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] ${isActive ? 'bg-surface-2 text-ink' : 'text-muted hover:text-ink'}`}>
              <Icon name="settings" />Settings
            </NavLink>
          </div>
        </aside>
        <div className="flex min-w-0 flex-col">
          <header className="sticky top-0 z-20 flex h-12 items-center justify-between gap-3 border-b border-line bg-bg px-5">
            <button className="btn h-9 lg:hidden" onClick={() => setMenu((m) => !m)} aria-expanded={menu} aria-controls="mobile-nav">Menu</button>
            <span className="hidden text-[12px] text-muted lg:block">NLP · URL model · brand look-alikes · threat intelligence · infrastructure graph</span>
            <LinkBadge state={live.state} />
          </header>
          {menu && <nav id="mobile-nav" className="space-y-0.5 border-b border-line bg-[#0a0d11] p-2.5 lg:hidden" aria-label="Main"><NavItems onPick={() => setMenu(false)} /></nav>}
          <main id="main" className="min-w-0 flex-1 px-5 py-6 lg:px-8">
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
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Suspense>
          </main>
        </div>
      </div>
    </LiveCtx.Provider>
  );
}
