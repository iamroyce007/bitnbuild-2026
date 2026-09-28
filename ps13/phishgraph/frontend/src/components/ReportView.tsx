import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import type { Report } from '../lib/types';
import { DECISION_COLOR, DemoTag, ReasonList, RiskNumber, ScoreRow, Section, riskColor } from './ui';

const SCORE_LABEL: Record<string, string> = { nlp: 'Language (NLP)', url: 'Link / URL model', brand: 'Brand impersonation', metadata: 'Sender & headers', threat_intelligence: 'Threat intelligence', graph: 'Infrastructure graph' };
const INTENT_COLOR = '#e0a10633';

function Highlighted({ text, spans }: { text: string; spans: { start: number; end: number; intent: string }[] }) {
  const s = [...spans].sort((a, b) => a.start - b.start).filter((x, i, arr) => i === 0 || x.start >= arr[i - 1].end);
  const out: React.ReactNode[] = [];
  let at = 0;
  for (const x of s) {
    if (x.start > at) out.push(text.slice(at, x.start));
    out.push(<mark key={x.start} title={x.intent.replace(/_/g, ' ')} className="rounded-sm px-0.5 text-ink" style={{ background: INTENT_COLOR, boxShadow: 'inset 0 -1px 0 #e0a106' }}>{text.slice(x.start, x.end)}</mark>);
    at = x.end;
  }
  out.push(text.slice(at));
  return <div className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-md border border-line bg-bg p-3 text-[13px] leading-relaxed">{out}</div>;
}

function Feedback({ id, status }: { id: string; status?: string }) {
  const [done, setDone] = useState<string | null>(status && status !== 'open' ? status : null);
  const [msg, setMsg] = useState('');
  const send = async (label: 'confirmed_phishing' | 'false_positive' | 'unsure') => {
    try {
      const r = await api.feedback(id, label);
      setDone(label);
      setMsg(label === 'confirmed_phishing' ? `${r.iocs_added} indicator(s) added to the local threat feed.` : label === 'false_positive' ? 'Queued as a hard negative for retraining.' : 'Recorded.');
    } catch (e) {
      setMsg(e instanceof Error ? e.message : 'Failed');
    }
  };
  return (
    <div className="flex flex-wrap items-center gap-2">
      <button className="btn" disabled={!!done} onClick={() => send('confirmed_phishing')}>Confirm phishing</button>
      <button className="btn" disabled={!!done} onClick={() => send('false_positive')}>False positive</button>
      <button className="btn btn-ghost" disabled={!!done} onClick={() => send('unsure')}>Unsure</button>
      {(done || msg) && <span className="text-[12px] text-muted" role="status">{done ? `Marked ${done.replace('_', ' ')}. ` : ''}{msg}</span>}
    </div>
  );
}

export default function ReportView({ r, status }: { r: Report; status?: string }) {
  const m = r.message;
  const textForHighlight = m.subject && m.text.startsWith(m.subject) ? m.text : m.text;
  return (
    <div className="space-y-5">
      {/* verdict */}
      <section className="card grid gap-6 p-5 lg:grid-cols-[auto_1fr_auto]" style={{ borderTop: `3px solid ${DECISION_COLOR[r.decision]}` }}>
        <RiskNumber value={r.risk_score} decision={r.decision} />
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="truncate text-[16px] font-semibold">{r.title}</h2>
            {r.demo && <DemoTag />}
          </div>
          <div className="mt-1 text-[13px] text-muted">
            {m.channel} {m.sender && <>· from <span className="font-mono text-ink">{m.sender_name ? `${m.sender_name} <${m.sender}>` : m.sender}</span></>}
          </div>
          {r.response && <div className="mt-2 text-[13px]"><span className="label mr-2">Response</span>{r.response.result} <span className="font-mono text-faint">({r.response.mode})</span></div>}
          {r.campaign?.id && <div className="mt-1 text-[13px]"><span className="label mr-2">Campaign</span><Link className="font-mono text-accent hover:underline" to={`/campaigns/${r.campaign.id}`}>{r.campaign.id}</Link> <span className="text-faint">similarity {r.campaign.similarity.toFixed(2)}</span></div>}
        </div>
        <div className="text-right font-mono text-[12px] text-faint">
          <div>{r.latency_ms} ms</div>
          <div>{r.deep_analysis ? 'full enrichment' : 'fast path'}</div>
        </div>
      </section>

      {r.conflicting_intelligence && (
        <div role="note" className="rounded-md border border-[#4a3a0e] bg-[#e0a10610] px-4 py-2.5 text-[13px]"><span className="font-semibold text-flag">Conflicting intelligence.</span> {r.conflict_detail}</div>
      )}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="space-y-5 min-w-0">
          <Section title="Why this decision" right={<span className="text-[12px] text-faint">evidence weight</span>}>
            <ReasonList reasons={r.reasons} limit={14} />
            {!!r.overrides.length && (
              <div className="mt-3 border-t border-line pt-3 text-[12px] text-muted">
                <span className="label mr-2">Rules applied</span>{r.overrides.join(' · ')}
              </div>
            )}
          </Section>

          {m.text && (
            <Section title="Message" right={<span className="text-[12px] text-faint">highlighted: phrases matched by intent detection</span>}>
              <Highlighted text={textForHighlight} spans={m.highlights || []} />
              {!!m.tricks.length && (
                <ul className="mt-3 space-y-1 text-[13px]">
                  {m.tricks.map((t) => <li key={t.id}><span className="label mr-2">Evasion</span>{t.label}{t.evidence && <span className="ml-1 font-mono text-[12px] text-faint">{t.evidence.slice(0, 80)}</span>}</li>)}
                </ul>
              )}
              {!!m.attachments.length && (
                <ul className="mt-3 space-y-1 text-[13px]">
                  {m.attachments.map((a) => <li key={a.sha256}><span className="label mr-2">Attachment</span><span className="font-mono">{a.filename}</span> <span className="text-faint">sha256 {a.sha256.slice(0, 16)}…</span>{(a.risky || a.double_extension) && <span className="ml-2 text-quarantine">risky type</span>}</li>)}
                </ul>
              )}
            </Section>
          )}

          <Section title={`Links (${r.urls.length})`} flush>
            {!r.urls.length ? <div className="p-4 text-[13px] text-muted">No links found in this message.</div> : (
              <ul className="divide-y divide-line">
                {r.urls.map((u) => {
                  const e = u.enrichment || {};
                  return (
                    <li key={u.url} className="space-y-2 p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="break-all font-mono text-[13px]">{u.url}</div>
                          {u.display !== u.host && <div className="font-mono text-[12px] text-quarantine">displays as {u.display}</div>}
                        </div>
                        <span className="font-mono text-[15px] font-medium" style={{ color: riskColor(u.score) }}>{Math.round(u.score)}</span>
                      </div>
                      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[12px] text-muted">
                        {u.brand?.official && <span>official domain of <span className="text-ink">{u.brand.official}</span></span>}
                        {u.brand?.tranco_rank && <span>Tranco rank {u.brand.tranco_rank.toLocaleString()}</span>}
                        {u.ml_probability != null && <span>URL model {Math.round(u.ml_probability * 100)}%</span>}
                        {e.rdap?.age_days != null && <span>registered {e.rdap.age_days} days ago</span>}
                        {e.dns?.a?.length > 0 && <span className="font-mono">{e.dns.a[0]}</span>}
                        {e.asn?.[0] && <span className="font-mono">{e.asn[0].asn} {e.asn[0].name}</span>}
                        {e.demo && <DemoTag />}
                      </div>
                      {!!u.rules.length && <ul className="space-y-0.5 text-[13px]">{u.rules.map((x) => <li key={x.id}>– {x.label}</li>)}</ul>}
                      {!!u.top_ngrams.length && !u.trusted && <div className="text-[12px] text-faint">URL model weight on: {u.top_ngrams.map(([g]) => <code key={g} className="mx-0.5 rounded bg-surface-2 px-1 text-muted">{g}</code>)}</div>}
                    </li>
                  );
                })}
              </ul>
            )}
          </Section>

          {!!r.graph.paths.length && (
            <Section title="Infrastructure graph evidence" right={<span className="font-mono text-[12px] text-faint">data: {r.graph.data_quality}</span>}>
              <ul className="space-y-2">
                {r.graph.paths.map((p, i) => (
                  <li key={i} className="text-[13px]">
                    <div>{p.text}</div>
                    <div className="mt-1 flex flex-wrap items-center gap-1 font-mono text-[11px] text-faint">
                      {p.nodes.map((n, j) => <span key={j} className="rounded border border-line px-1.5 py-px">{n.type}: {n.label.slice(0, 36)}</span>)}
                    </div>
                  </li>
                ))}
              </ul>
            </Section>
          )}
        </div>

        <div className="space-y-5">
          <Section title="Engine scores">
            {Object.keys(SCORE_LABEL).map((k) => <ScoreRow key={k} label={SCORE_LABEL[k]} value={r.scores[k]} note={r.weights_used[k] != null ? `weight ${r.weights_used[k]}` : 'unavailable: weight redistributed'} />)}
            {!!r.unavailable_sources.length && <p className="mt-2 text-[12px] text-faint">n/a = no evidence from that source; its weight was redistributed rather than counted as safe.</p>}
          </Section>

          <Section title="Threat intelligence" flush>
            <table className="tbl">
              <tbody>
                {r.threat_intel.sources.map((s) => (
                  <tr key={s.source}>
                    <td className="font-mono text-[12px]">{s.source}</td>
                    <td className="text-right">
                      <span className={`font-mono text-[11px] ${s.verdict === 'malicious' ? 'text-block' : s.status === 'ok' ? 'text-muted' : 'text-faint'}`}>{s.verdict === 'malicious' ? 'MALICIOUS' : s.display}</span>
                      {s.status === 'ok' && <div className="text-[12px] text-faint">{s.summary}</div>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>

          {r.nlp && (
            <Section title="Language analysis">
              <div className="mb-2 grid grid-cols-2 gap-2 font-mono text-[12px] text-muted">
                <span>TF-IDF model {r.nlp.p_stage1 != null ? `${Math.round(r.nlp.p_stage1 * 100)}%` : 'n/a'}</span>
                <span>Semantic model {r.nlp.p_stage2 != null ? `${Math.round(r.nlp.p_stage2 * 100)}%` : 'off'}</span>
              </div>
              {r.nlp.intents.length ? (
                <ul className="space-y-1.5 text-[13px]">
                  {r.nlp.intents.map((i) => <li key={i.id}>{i.label} <span className="text-faint">{i.source === 'semantic' ? `(paraphrase, ${i.similarity})` : ''}</span></li>)}
                </ul>
              ) : <p className="text-[13px] text-muted">No scam intent detected.</p>}
              {!!r.nlp.top_terms.length && <div className="mt-3 text-[12px] text-faint">Top terms: {r.nlp.top_terms.slice(0, 6).map(([t]) => t).join(', ')}</div>}
            </Section>
          )}

          {r.timeline.length > 1 && (
            <Section title="Deception timeline">
              <ol className="relative space-y-3 border-l border-line pl-4">
                {r.timeline.map((t, i) => (
                  <li key={i} className="text-[13px]">
                    <span className="absolute -left-[4px] mt-1.5 size-[7px] rounded-full bg-line-strong" />
                    <div className="font-mono text-[11px] text-faint">{new Date(t.at).toLocaleString()} · {t.source}</div>
                    <div>{t.event}</div>
                  </li>
                ))}
              </ol>
            </Section>
          )}

          <Section title="Analyst verdict"><Feedback id={r.detection_id} status={status} /></Section>
        </div>
      </div>
    </div>
  );
}
