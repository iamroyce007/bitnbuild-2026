// Live detection stream: WebSocket first, automatic reconnect, polling fallback where WebSockets are unavailable
// (e.g. serverless deployments).
import { useEffect, useRef, useState } from 'react';
import { apiBase, getKey } from './api';
import type { LiveEvent } from './types';

export type LinkState = 'live' | 'polling' | 'offline';

export function useEvents(onEvent?: (e: LiveEvent) => void) {
  const [state, setState] = useState<LinkState>('offline');
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const cb = useRef(onEvent);
  cb.current = onEvent;

  useEffect(() => {
    let ws: WebSocket | null = null;
    let stopped = false;
    let retry = 1000;
    let pollTimer: number | undefined;
    let wsFailures = 0;
    let lastAt = '';

    const push = (e: LiveEvent) => {
      if (e.event === 'ping' || e.event === 'hello') return;
      setEvents((xs) => [e, ...xs].slice(0, 200));
      cb.current?.(e);
    };

    const poll = async () => {
      try {
        const r = await fetch(`${apiBase()}/api/v1/events/recent?since=${encodeURIComponent(lastAt)}`, { headers: { 'X-API-Key': getKey() } });
        if (r.ok) {
          const xs: LiveEvent[] = await r.json();
          for (const e of xs) push(e);
          if (xs.length) lastAt = xs[xs.length - 1].at || lastAt;
          setState('polling');
        } else setState('offline');
      } catch {
        setState('offline');
      }
      if (!stopped) pollTimer = window.setTimeout(poll, 4000);
    };

    const connect = () => {
      const base = apiBase() || window.location.origin;
      const url = base.replace(/^http/, 'ws') + `/api/v1/events?api_key=${encodeURIComponent(getKey())}`;
      ws = new WebSocket(url);
      ws.onopen = () => {
        retry = 1000;
        wsFailures = 0;
        setState('live');
      };
      ws.onmessage = (m) => {
        const e = JSON.parse(m.data) as LiveEvent & { recent?: LiveEvent[] };
        if (e.event === 'hello') {
          lastAt = e.recent?.length ? e.recent[e.recent.length - 1].at || '' : '';
          return;
        }
        push(e);
      };
      ws.onclose = () => {
        if (stopped) return;
        wsFailures += 1;
        if (wsFailures >= 3) {
          poll(); // WebSockets not available here: fall back to polling
          return;
        }
        setState('offline');
        window.setTimeout(connect, retry);
        retry = Math.min(15000, retry * 2);
      };
    };
    connect();
    return () => {
      stopped = true;
      ws?.close();
      window.clearTimeout(pollTimer);
    };
  }, []);

  return { state, events };
}
