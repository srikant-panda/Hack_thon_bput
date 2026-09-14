import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ChevronDown, ChevronUp, Loader2, RefreshCw, ScrollText } from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import { useUiStore } from '../store/uiStore';
import * as orgApi from '../services/orgApi';

const LOG_TYPE_STYLES: Record<string, string> = {
  connection: 'bg-sky-500/15 text-sky-400 ring-sky-500/40',
  scan: 'bg-violet-500/15 text-violet-400 ring-violet-500/40',
  quarantine: 'bg-amber-500/15 text-amber-400 ring-amber-500/40',
  error: 'bg-red-500/15 text-red-400 ring-red-500/40',
};

/**
 * ORG-3: per-mail-server log stream (grouped BY server — this page always
 * shows exactly one server's stream, never a combined feed).
 */
export default function OrgMailServerLogs() {
  const { orgId, serverId } = useParams<{ orgId: string; serverId: string }>();
  const addToast = useUiStore((s) => s.addToast);
  const [logs, setLogs] = useState<orgApi.MailServerLog[]>([]);
  const [server, setServer] = useState<orgApi.MailServer | null>(null);
  const [loading, setLoading] = useState(true);
  const [logType, setLogType] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!orgId || !serverId) return;
    try {
      const [logList, servers] = await Promise.all([
        orgApi.listMailServerLogs(orgId, serverId, { limit: 200, log_type: logType || null }),
        orgApi.listMailServers(orgId),
      ]);
      setLogs(logList);
      setServer(servers.find((s) => s.id === serverId) ?? null);
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to load server logs', 'high');
    } finally {
      setLoading(false);
    }
  }, [orgId, serverId, logType, addToast]);

  useEffect(() => {
    load();
  }, [load]);

  if (!orgId || !serverId) return <div className="p-6 text-sm text-zinc-400">No mail server selected.</div>;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <PageHeader
          title={`Logs — ${server?.name ?? 'Mail Server'}`}
          description="This server's own log stream (connection, scan, quarantine, error) — grouped by server, never combined."
        />
        <div className="flex items-center gap-2">
          <Link
            to={`/org/${orgId}/mail-servers`}
            className="rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-200 transition hover:border-zinc-500"
          >
            All servers
          </Link>
          <select
            value={logType}
            onChange={(e) => setLogType(e.target.value)}
            className="rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-500/60"
          >
            <option value="">All types</option>
            <option value="connection">Connection</option>
            <option value="scan">Scan</option>
            <option value="quarantine">Quarantine</option>
            <option value="error">Error</option>
          </select>
          <button
            onClick={load}
            className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-200 transition hover:border-zinc-500"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </div>

      <div className="space-y-2">
        {loading && (
          <div className="flex items-center gap-2 py-8 text-xs text-zinc-500">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading server log stream…
          </div>
        )}
        {!loading && logs.length === 0 && (
          <div className="flex items-center justify-center gap-2 rounded-xl border border-zinc-800 bg-zinc-900/90 p-8 text-xs text-zinc-500 backdrop-blur">
            <ScrollText className="h-4 w-4" />
            No logs yet for this mail server
          </div>
        )}
        {logs.map((log) => (
          <div key={log.id} className="rounded-lg border border-zinc-800 bg-zinc-900/90 px-4 py-3 backdrop-blur">
            <button
              onClick={() => setExpanded(expanded === log.id ? null : log.id)}
              className="flex w-full items-center gap-3 text-left"
            >
              <span className="w-32 shrink-0 font-mono text-[11px] text-zinc-500">
                {log.created_at ? new Date(log.created_at).toLocaleString() : '—'}
              </span>
              <span className={`inline-flex w-24 shrink-0 items-center justify-center rounded px-2 py-0.5 font-mono text-[10px] uppercase ring-1 ${LOG_TYPE_STYLES[log.log_type] ?? ''}`}>
                {log.log_type}
              </span>
              <span className="min-w-0 flex-1 truncate text-xs text-zinc-300">{log.message}</span>
              {log.metadata && Object.keys(log.metadata).length > 0 && (
                expanded === log.id ? <ChevronUp className="h-4 w-4 shrink-0 text-zinc-500" /> : <ChevronDown className="h-4 w-4 shrink-0 text-zinc-500" />
              )}
            </button>
            {expanded === log.id && log.metadata && (
              <pre className="mt-3 overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-950 p-3 font-mono text-[11px] leading-relaxed text-zinc-300">
                {JSON.stringify(log.metadata, null, 2)}
              </pre>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
