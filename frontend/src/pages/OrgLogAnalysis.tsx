import { useCallback, useEffect, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import {
  Ban,
  CircleSlash,
  Loader2,
  Network,
  RefreshCw,
  ShieldCheck,
  Terminal,
  UserX,
  Zap,
} from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import { useUiStore } from '../store/uiStore';
import { useOrgRealtime } from '../hooks/useOrgRealtime';
import * as orgApi from '../services/orgApi';

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 ring-red-500/40',
  high: 'bg-orange-500/15 text-orange-400 ring-orange-500/40',
  medium: 'bg-amber-500/15 text-amber-400 ring-amber-500/40',
  low: 'bg-sky-500/15 text-sky-400 ring-sky-500/40',
  safe: 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/30',
};

const LOG_TYPE_STYLES: Record<orgApi.LogType, string> = {
  auth: 'bg-violet-500/15 text-violet-400 ring-violet-500/40',
  network: 'bg-cyan-500/15 text-cyan-400 ring-cyan-500/40',
  app: 'bg-zinc-700/40 text-zinc-300 ring-zinc-600/50',
};

const LOG_TYPE_ICONS = { auth: UserX, network: Network, app: Terminal };

/** Manual actions per log type (analyst+ only; backend re-checks RBAC). */
const ACTIONS_BY_TYPE: Record<orgApi.LogType, Array<{ action: orgApi.LogAction; label: string; icon: typeof Ban }>> = {
  auth: [
    { action: 'block_ip', label: 'Block IP', icon: Ban },
    { action: 'revoke_session', label: 'Revoke Session', icon: UserX },
  ],
  network: [
    { action: 'block_ip', label: 'Block IP', icon: Ban },
    { action: 'isolate_host', label: 'Isolate Host', icon: CircleSlash },
  ],
  app: [
    { action: 'escalate_incident', label: 'Escalate Incident', icon: Zap },
    { action: 'mark_safe', label: 'Mark Safe', icon: ShieldCheck },
  ],
};

function summarize(e: orgApi.OrgLogEvent): string {
  const result = e.analysis_result as Record<string, unknown>;
  if (typeof result.summary === 'string' && result.summary) return result.summary;
  const raw = e.raw_data as Record<string, unknown>;
  if (typeof raw?.message === 'string') return raw.message;
  return JSON.stringify(e.raw_data).slice(0, 120);
}

/**
 * ORG-2: Splunk-style live log analysis — scrolling stream of gateway-ingested
 * logs with per-type auto-analysis and manual analyst actions on the same
 * plane. Live via Supabase postgres_changes; 5 s fallback polling.
 */
export default function OrgLogAnalysis() {
  const { orgId } = useParams<{ orgId: string }>();
  const addToast = useUiStore((s) => s.addToast);
  const [events, setEvents] = useState<orgApi.OrgLogEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [live, setLive] = useState(false);
  const [filterType, setFilterType] = useState('');
  const [selected, setSelected] = useState<orgApi.OrgLogEvent | null>(null);
  const [actingId, setActingId] = useState<string | null>(null);
  const actionsInFlight = useRef(false);

  const load = useCallback(async () => {
    if (!orgId || actionsInFlight.current) return;
    try {
      const list = await orgApi.getLogStream(orgId, { limit: 100, log_type: filterType || null });
      setEvents(list);
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to load log stream', 'high');
    } finally {
      setLoading(false);
    }
  }, [orgId, filterType, addToast]);

  useEffect(() => {
    load();
  }, [load]);

  useOrgRealtime('org_log_events', orgId, () => {
    setLive(true);
    load();
  });

  useEffect(() => {
    if (!orgId) return;
    const t = setInterval(load, 5000); // fallback when realtime is unavailable
    return () => clearInterval(t);
  }, [orgId, load]);

  const takeAction = async (e: orgApi.OrgLogEvent, action: orgApi.LogAction) => {
    if (!orgId) return;
    const target =
      action === 'block_ip' || action === 'isolate_host'
        ? (e.analysis_result as Record<string, unknown>).source_ip as string | undefined ||
          (e.raw_data as Record<string, unknown>).src_ip as string | undefined
        : undefined;
    setActingId(e.id);
    actionsInFlight.current = true;
    try {
      await orgApi.takeLogAction(orgId, e.id, action, target);
      addToast(`Action recorded: ${action.replace('_', ' ')}`, 'safe');
      await load();
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Action failed', 'high');
    } finally {
      actionsInFlight.current = false;
      setActingId(null);
    }
  };

  if (!orgId) return <div className="p-6 text-sm text-zinc-400">No organization selected.</div>;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <PageHeader
          title="Live Log Analysis"
          description="Splunk-style stream of gateway-ingested logs — auto-analyzed, with manual analyst actions on the same plane."
        />
        <div className="flex items-center gap-2">
          <span
            className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-[10px] uppercase ring-1 ${
              live ? 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/30' : 'bg-zinc-800 text-zinc-400 ring-zinc-600/40'
            }`}
          >
            {live ? 'Live' : 'Polling'}
          </span>
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-500/60"
          >
            <option value="">All types</option>
            <option value="auth">Auth</option>
            <option value="network">Network</option>
            <option value="app">App</option>
          </select>
          <button
            onClick={load}
            className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-200 transition hover:border-zinc-500"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </div>

      {/* Live stream */}
      <div className="space-y-2">
        {loading && (
          <div className="flex items-center gap-2 py-8 text-xs text-zinc-500">
            <Loader2 className="h-4 w-4 animate-spin" /> Connecting to log stream…
          </div>
        )}
        {!loading && events.length === 0 && (
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-8 text-center text-xs text-zinc-500 backdrop-blur">
            No logs ingested yet — point your SIEM or scripts at{' '}
            <code className="font-mono text-zinc-400">POST /api/v1/org/{orgId}/logs/ingest</code> with an
            <code className="font-mono text-zinc-400"> org_authorization</code> API key.
          </div>
        )}
        {events.map((e) => {
          const TypeIcon = LOG_TYPE_ICONS[e.log_type] ?? Terminal;
          const resolved = Boolean(e.manual_action_taken);
          return (
            <div
              key={e.id}
              className="group flex flex-col gap-2 rounded-lg border border-zinc-800 bg-zinc-900/90 px-4 py-3 backdrop-blur transition hover:border-zinc-600 sm:flex-row sm:items-center"
            >
              <span className="w-36 shrink-0 font-mono text-[11px] text-zinc-500">
                {e.created_at ? new Date(e.created_at).toLocaleTimeString() : '—'}
              </span>
              <span className={`inline-flex w-20 shrink-0 items-center justify-center gap-1 rounded px-2 py-0.5 font-mono text-[10px] uppercase ring-1 ${LOG_TYPE_STYLES[e.log_type]}`}>
                <TypeIcon className="h-3 w-3" /> {e.log_type}
              </span>
              <span className={`inline-flex w-20 shrink-0 items-center justify-center rounded px-2 py-0.5 text-[10px] font-bold uppercase ring-1 ${SEVERITY_STYLES[e.severity] ?? ''}`}>
                {e.severity}
              </span>
              <button
                onClick={() => setSelected(e)}
                className="min-w-0 flex-1 truncate text-left text-xs text-zinc-300 hover:text-zinc-100"
                title={summarize(e)}
              >
                {summarize(e)}
              </button>
              {resolved ? (
                <span className="shrink-0 rounded bg-zinc-800 px-2 py-1 font-mono text-[10px] text-zinc-300">
                  ✓ {e.manual_action_taken}
                </span>
              ) : (
                <div className="flex shrink-0 gap-1.5 opacity-0 transition group-hover:opacity-100">
                  {ACTIONS_BY_TYPE[e.log_type]?.map((a) => {
                    const Icon = a.icon;
                    return (
                      <button
                        key={a.action}
                        onClick={() => takeAction(e, a.action)}
                        disabled={actingId === e.id}
                        className="inline-flex items-center gap-1 rounded border border-red-500/40 px-2 py-1 text-[11px] text-red-400 transition hover:bg-red-500/10 disabled:opacity-50"
                      >
                        {actingId === e.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Icon className="h-3 w-3" />}
                        {a.label}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Detail drawer */}
      {selected && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/70" onClick={() => setSelected(null)}>
          <div
            className="h-full w-full max-w-xl overflow-y-auto border-l border-zinc-800 bg-zinc-900 p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-sm font-bold text-zinc-100">Log Detail</h3>
              <button onClick={() => setSelected(null)} className="text-xs text-zinc-400 hover:text-zinc-200">Close</button>
            </div>
            <div className="mb-3 flex items-center gap-2">
              <span className={`rounded px-2 py-0.5 font-mono text-[10px] uppercase ring-1 ${LOG_TYPE_STYLES[selected.log_type]}`}>
                {selected.log_type}
              </span>
              <span className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase ring-1 ${SEVERITY_STYLES[selected.severity] ?? ''}`}>
                {selected.severity}
              </span>
              {selected.manual_action_taken && (
                <span className="rounded bg-zinc-800 px-2 py-0.5 font-mono text-[10px] text-zinc-300">
                  action: {selected.manual_action_taken}
                </span>
              )}
            </div>
            {(selected.analysis_result as Record<string, unknown>).risk_score !== undefined && (
              <p className="mb-3 font-mono text-xs text-zinc-400">risk score: {String((selected.analysis_result as Record<string, unknown>).risk_score)}</p>
            )}
            <h4 className="font-mono text-[11px] uppercase tracking-wider text-zinc-500">Analysis</h4>
            <pre className="mt-2 overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-950 p-3 font-mono text-[11px] leading-relaxed text-zinc-300">
              {JSON.stringify(selected.analysis_result, null, 2)}
            </pre>
            <h4 className="mt-4 font-mono text-[11px] uppercase tracking-wider text-zinc-500">Raw Log</h4>
            <pre className="mt-2 overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-950 p-3 font-mono text-[11px] leading-relaxed text-zinc-300">
              {JSON.stringify(selected.raw_data, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
