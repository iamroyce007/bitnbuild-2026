export type Decision = 'ALLOW' | 'FLAG' | 'QUARANTINE' | 'BLOCK';

export interface Reason {
  category: string;
  text: string;
  weight: number;
  source: string;
}

export interface UrlReport {
  url: string;
  display: string;
  host: string;
  registrable: string;
  score: number;
  ml_probability: number | null;
  trusted: boolean;
  rules: { id: string; label: string; weight: number }[];
  top_ngrams: [string, number][];
  sources: string[];
  unwrapped: string[];
  deceptive_text: string | null;
  brand: { official: string | null; tranco_rank: number | null; established: boolean; findings: { kind: string; target_domain: string; brand: string | null; confidence: number; evidence: string }[]; scripts: string[] } | null;
  enrichment: Record<string, any> | null;
}

export interface TISource {
  source: string;
  status: string;
  display: string;
  verdict: string | null;
  summary: string;
  lookups: number;
  cached: number;
}

export interface GraphPath {
  kind: string;
  weight: number;
  text: string;
  nodes: { id: string; type: string; label: string }[];
}

export interface Report {
  detection_id: string;
  title: string;
  risk_score: number;
  decision: Decision;
  scores: Record<string, number | null>;
  weights_used: Record<string, number>;
  unavailable_sources: string[];
  overrides: string[];
  conflicting_intelligence: boolean;
  conflict_detail: string | null;
  reasons: Reason[];
  message: {
    channel: string; sender: string; sender_name: string; subject: string; text: string; reply_to: string; auth: Record<string, string>;
    attachments: { filename: string; sha256: string; extension: string; risky: boolean; double_extension: boolean }[];
    indicators: Record<string, string[]>; tricks: { id: string; label: string; evidence?: string }[]; highlights: { start: number; end: number; intent: string }[];
  };
  nlp: null | { score: number; p_stage1: number | null; p_stage2: number | null; intent_score: number; intents: { id: string; label: string; weight: number; evidence: string[]; source: string; similarity: number | null }[]; top_terms: [string, number][]; campaign_similarity: number | null; semantic_available: boolean };
  urls: UrlReport[];
  metadata: { score: number; signals: { id: string; label: string; weight: number; evidence: string }[]; claimed_brands: string[]; sender: Record<string, unknown> | null };
  threat_intel: { score: number | null; sources: TISource[]; external_enabled: boolean };
  graph: { score: number; components: Record<string, number>; paths: GraphPath[]; data_quality: string };
  campaign: null | { id: string | null; best_match: { id: string; name: string; semantic: number; infrastructure: number } | null; similarity: number };
  timeline: { at: string; event: string; source: string }[];
  response?: { action: string; mode: string; target: string; result: string };
  deep_analysis: boolean;
  latency_ms: number;
  demo: boolean;
  analyzed_at: string;
}

export interface Analysis {
  detection_id: string;
  risk_score: number;
  decision: Decision;
  scores: Record<string, number | null>;
  reasons: Reason[];
  urls: UrlReport[];
  campaign: Report['campaign'];
  conflicting_intelligence: boolean;
  latency_ms: number;
  report: Report;
}

export interface DetectionSummary {
  detection_id: string;
  kind: string;
  title: string;
  risk_score: number;
  decision: Decision;
  scores: Record<string, number | null>;
  campaign_id: string | null;
  status: string;
  demo: boolean;
  conflicting_intelligence: boolean;
  latency_ms: number;
  created_at: string;
  top_reason: string | null;
  channel: string | null;
}

export interface DetectionDetail extends DetectionSummary {
  report: Report;
  actions: { action: string; mode: string; target: string; result: string; at: string }[];
  feedback: { label: string; analyst: string; note: string; at: string }[];
  model_versions: Record<string, string>;
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  risk: number | null;
  malicious: boolean;
  first_seen?: string;
  last_seen?: string;
  focus?: boolean;
  [k: string]: unknown;
}
export interface GraphEdge {
  source: string;
  target: string;
  rel: string;
  first_seen?: string;
  last_seen?: string;
  source_system?: string;
  confidence?: number;
}
export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface CampaignSummary {
  id: string;
  name: string;
  risk: number;
  brands: string[];
  stats: Record<string, number>;
  first_seen: string;
  last_seen: string;
  demo: boolean;
}
export interface CampaignDetail extends CampaignSummary {
  detections: DetectionSummary[];
  graph: GraphData;
}

export interface Statistics {
  total_detections: number;
  window_hours: number;
  by_decision: Partial<Record<Decision, number>>;
  avg_latency_ms: number;
  campaigns: number;
  feedback: Record<string, number>;
  timeseries: ({ t: string } & Record<Decision, number>)[];
  risk_histogram: number[];
  graph: { backend: string; nodes: number; edges: number; by_type: Record<string, number> };
  threat_feed_size: number;
}

export interface ThreatFeed {
  counts: Record<string, number>;
  feeds: Record<string, Record<string, unknown>>;
  iocs: { type: string; value: string; source: string; tags: string[]; demo: boolean; first_seen: string }[];
}

export interface ProviderHealth {
  name: string;
  state: string;
  configured: boolean;
  enabled: boolean;
  external: boolean;
  calls: number;
  errors: number;
  avg_latency_ms: number | null;
  last_error: string | null;
  last_ok: number | null;
  supports: string[];
}
export interface ProvidersInfo {
  providers: ProviderHealth[];
  feeds: Record<string, Record<string, unknown>>;
}

export interface ModelsInfo {
  registry: { name: string; version: number; status: string; trained_at: string; artifact: string; sha256_16: string; splits: Record<string, Record<string, any>>; data: Record<string, any>; notes?: string[] }[];
  training_queue: Record<string, number>;
  drift: Record<string, any>;
}

export interface LiveEvent {
  event: string;
  detection_id?: string;
  risk?: number;
  previous_risk?: number;
  decision?: Decision;
  title?: string;
  campaign_id?: string | null;
  at?: string;
  demo?: boolean;
  label?: string;
}
