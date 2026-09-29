// Typed API client. Public servers need no key. A private server's key can arrive once via a #key= setup link and
// then lives in localStorage; the dashboard never asks for one. Requests go to the same origin
// (the FastAPI server serves the built dashboard; Vite proxies in development).
import type { Analysis, CampaignDetail, CampaignSummary, DetectionDetail, DetectionSummary, GraphData, ModelsInfo, ProvidersInfo, Statistics, ThreatFeed } from './types';

const KEY = 'phishgraph.apiKey';
const isLocal = ['localhost', '127.0.0.1'].includes(window.location.hostname);
export const getKey = () => localStorage.getItem(KEY) || (isLocal ? 'dev-local-key' : '');
export const setKey = (k: string) => localStorage.setItem(KEY, k);

// One-click setup links: https://host/#key=...  (the fragment never reaches any server; removed from the URL at once)
(() => {
  const m = window.location.hash.match(/key=([^&]+)/);
  if (m) {
    setKey(decodeURIComponent(m[1]));
    history.replaceState(null, '', window.location.pathname + window.location.search);
  }
})();
export const apiBase = () => (import.meta.env.VITE_API_BASE as string | undefined) || '';

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${apiBase()}${path}`, {
    ...init,
    headers: { 'content-type': 'application/json', ...(getKey() ? { 'X-API-Key': getKey() } : {}), ...(init?.headers || {}) },
  });
  if (!r.ok) {
    let detail = r.statusText;
    try {
      const j = await r.json();
      detail = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail);
    } catch {
      /* not json */
    }
    throw new ApiError(r.status, detail);
  }
  return r.json() as Promise<T>;
}

const post = <T>(path: string, body: unknown) => req<T>(path, { method: 'POST', body: JSON.stringify(body) });

export const api = {
  analyzeEmail: (b: { subject?: string; sender?: string; body?: string; html?: string; raw?: string; channel?: string; deep?: boolean }) => post<Analysis>('/api/v1/analyze/email', b),
  analyzeUrl: (url: string, deep = false) => post<Analysis>('/api/v1/analyze/url', { url, deep }),
  investigate: (url: string) => post<{ job_id: string }>('/api/v1/investigate', { url }),
  job: (id: string) => req<{ status: string; result: Record<string, unknown> | null; error: string | null }>(`/api/v1/jobs/${id}`),
  detections: (q = '') => req<DetectionSummary[]>(`/api/v1/detections${q}`),
  detection: (id: string) => req<DetectionDetail>(`/api/v1/detection/${id}`),
  graphDetection: (id: string, depth = 3) => req<GraphData>(`/api/v1/graph/detection/${id}?depth=${depth}`),
  graphDomain: (d: string) => req<GraphData>(`/api/v1/graph/domain/${encodeURIComponent(d)}`),
  graphOverview: () => req<GraphData & { stats: Statistics['graph'] }>('/api/v1/graph/overview'),
  domain: (d: string) => req<Record<string, unknown>>(`/api/v1/domain/${encodeURIComponent(d)}`),
  campaigns: () => req<CampaignSummary[]>('/api/v1/campaigns'),
  campaign: (id: string) => req<CampaignDetail>(`/api/v1/campaign/${id}`),
  feedback: (detection_id: string, label: 'confirmed_phishing' | 'false_positive' | 'unsure', note = '') =>
    post<{ iocs_added: number }>('/api/v1/feedback', { detection_id, label, note }),
  threatFeed: (q = '') => req<ThreatFeed>(`/api/v1/threat-feed${q}`),
  addIoc: (ioc_type: string, value: string) => post<{ added: number }>('/api/v1/threat-feed', { ioc_type, value }),
  statistics: (hours = 24) => req<Statistics>(`/api/v1/statistics?hours=${hours}`),
  providers: () => req<ProvidersInfo>('/api/v1/providers'),
  models: () => req<ModelsInfo>('/api/v1/models'),
  ready: () => req<Record<string, unknown>>('/ready'),
  sampleStatus: () => req<{ loaded: boolean; sample_detections: number; real_detections: number }>('/api/v1/sample-data'),
  loadSample: () => post<{ sample_detections: number; benign_allowed?: number; phishing_caught?: number }>('/api/v1/sample-data', {}),
  clearSample: () => req<{ sample_detections: number }>('/api/v1/sample-data', { method: 'DELETE' }),
  refreshFeeds: () => post<Record<string, Record<string, unknown>>>('/api/v1/feeds/refresh', {}),
  metrics: async () => (await fetch(`${apiBase()}/metrics`)).text(),
};
