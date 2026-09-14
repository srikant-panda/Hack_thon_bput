import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ChevronDown, ChevronUp, Loader2, RefreshCw, ScrollText } from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import { useUiStore } from '../store/uiStore';
import * as orgApi from '../services/orgApi';

const STATUS_STYLES: Record<string, string> = {
  sent: 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/30',
  failed: 'bg-red-500/15 text-red-400 ring-red-500/40',
  skipped: 'bg-zinc-700/30 text-zinc-400 ring-zinc-600/40',
};

const ROLE_STYLES: Record<string, string> = {
  admin: 'bg-red-500/15 text-red-400 ring-red-500/40',
  analyst: 'bg-amber-500/15 text-amber-400 ring-amber-500/40',
  viewer: 'bg-zinc-700/40 text-zinc-300 ring-zinc-600/50',
};

const EVENT_LABELS: Record<string, string> = {
  server_down: 'Server Down',
  mail_server_down: 'Mail Server Down',
  critical_log: 'Critical Log',
  impersonation: 'Impersonation',
};

const PAGE_SIZE = 25;

/**
 * ORG-4: dedicated notification delivery history with advanced filters
 * (event type, status, date range) and per-recipient outcome drawer.
 */
export default function OrgNotificationLog() {
  const { orgId } = useParams<{ orgId: string }>();
  const addToast = useUiStore((s) => s.addToast);
  const [logs, setLogs] = useState<orgApi.NotificationLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [, setPage] = useState(0);
  const [eventType, setEventType] = useState('');
  const [status, setStatus] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      setLogs(
        await orgApi.listNotificationLogs(orgId, {
          limit: PAGE_SIZE,
          event_type: eventType || null,
          status: status || null,
          from_date: fromDate ? new Date(fromDate).toISOString() : null,
          to_date: toDate ? new Date(toDate).toISOString() : null,
        }),
      );
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to load notification history', 'high');
    } finally {
      setLoading(false);
    }
  }, [orgId, eventType, status, fromDate, toDate, addToast]);

  useEffect(() => {
    load();
  }, [load]);

  if (!orgId) return <div className="p-6 text-sm text-zinc-400">No organization selected.</div>;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <PageHeader
          title="Notification Log History"
          description="Every org notification with per-recipient delivery outcomes."
        />
        <Link
          to={`/org/${orgId}/notifications`}
          className="self-start rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-200 transition hover:border-zinc-500"
        >
          Notification Settings
        </Link>
      </div>

      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-zinc-800 bg-zinc-900/90 p-4 backdrop-blur">
        <select value={eventType} onChange={(e) => { setEventType(e.target.value); setPage(0); }}
          className="rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-500/60">
          <option value="">All event types</option>
          {Object.entries(EVENT_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
        <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(0); }}
          className="rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-500/60">
          <option value="">All statuses</option>
          <option value="sent">Sent</option>
          <option value="failed">Failed</option>
          <option value="skipped">Skipped</option>
        </select>
        <label className="text-[11px] text-zinc-500">From</label>
        <input type="date" value={fromDate} onChange={(e) => { setFromDate(e.target.value); setPage(0); }}
          className="rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-500/60" />
        <label className="text-[11px] text-zinc-500">To</label>
        <input type="date" value={toDate} onChange={(e) => { setToDate(e.target.value); setPage(0); }}
          className="rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-500/60" />
        <button onClick={load} className="ml-auto inline-flex items-center gap-2 rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-200 transition hover:border-zinc-500">
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      <div className="space-y-2">
        {loading && <div className="flex items-center gap-2 py-8 text-xs text-zinc-500"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>}
        {!loading && logs.length === 0 && (
          <div className="flex items-center justify-center gap-2 rounded-xl border border-zinc-800 bg-zinc-900/90 p-8 text-xs text-zinc-500 backdrop-blur">
            <ScrollText className="h-4 w-4" /> No notification deliveries match these filters
          </div>
        )}
        {logs.map((log) => (
          <div key={log.id} className="rounded-lg border border-zinc-800 bg-zinc-900/90 px-4 py-3 backdrop-blur">
            <button onClick={() => setExpanded(expanded === log.id ? null : log.id)} className="flex w-full items-center gap-3 text-left">
              <span className="w-36 shrink-0 font-mono text-[11px] text-zinc-500">
                {log.created_at ? new Date(log.created_at).toLocaleString() : '—'}
              </span>
              <span className="w-32 shrink-0 font-mono text-[10px] uppercase text-zinc-400">{EVENT_LABELS[log.event_type] ?? log.event_type}</span>
              <span className="min-w-0 flex-1 truncate text-xs text-zinc-300">{log.subject}</span>
              <span className="shrink-0 text-[10px] text-zinc-500">{log.recipients.length} recipient(s)</span>
              <span className={`shrink-0 rounded px-2 py-0.5 text-[10px] uppercase ring-1 ${STATUS_STYLES[log.status]}`}>{log.status}</span>
              {expanded === log.id ? <ChevronUp className="h-3.5 w-3.5 shrink-0 text-zinc-500" /> : <ChevronDown className="h-3.5 w-3.5 shrink-0 text-zinc-500" />}
            </button>
            {expanded === log.id && (
              <div className="mt-3 space-y-2 border-t border-zinc-800 pt-3">
                {log.event_metadata && Object.keys(log.event_metadata).length > 0 && (
                  <pre className="overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-950 p-3 font-mono text-[11px] text-zinc-300">
                    {JSON.stringify(log.event_metadata, null, 2)}
                  </pre>
                )}
                {log.recipients.map((rec, i) => (
                  <div key={i} className="flex items-center gap-2 text-[11px]">
                    <span className={`rounded px-1.5 py-0.5 uppercase ring-1 ${STATUS_STYLES[rec.status] ?? ''}`}>{rec.status}</span>
                    <span className={`rounded-full px-1.5 py-0.5 text-[9px] uppercase ring-1 ${ROLE_STYLES[rec.role] ?? ''}`}>{rec.role}</span>
                    <span className="font-mono text-zinc-300">{rec.email}</span>
                    {rec.error_detail && <span className="text-red-400">{rec.error_detail}</span>}
                  </div>
                ))}
                {log.error_detail && <p className="text-[11px] text-red-400">{log.error_detail}</p>}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
