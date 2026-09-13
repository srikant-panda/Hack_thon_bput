import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Bell, Loader2, Mail, RefreshCw } from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import * as api from '../services/api';
import type { NotificationLogEntry } from '../types';

const STATUS_STYLES: Record<string, string> = {
  sent: 'bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/30',
  failed: 'bg-red-500/10 text-red-400 ring-1 ring-red-500/30',
};

function formatWhen(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

export default function NotificationLog() {
  const isMockMode = api.isMockMode();
  const [logs, setLogs] = useState<NotificationLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setLogs(await api.listNotificationLogs());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load notifications');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Notification Log"
        description="Every event email CYBERGUARD rendered and delivered to your registered notification address. Connected mailboxes are never used for system notifications."
      />

      {isMockMode && (
        <div className="flex items-center gap-2 rounded-lg border border-zinc-700/60 bg-zinc-800/40 px-3.5 py-2.5 text-xs text-zinc-300">
          <AlertTriangle className="h-4 w-4 text-amber-400" />
          <span className="font-mono font-bold tracking-wider">DEMO MODE — notifications require a real backend</span>
        </div>
      )}

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/10 px-3.5 py-2.5 text-sm text-red-300">
          <AlertTriangle className="h-4 w-4 text-red-400" />
          {error}
        </div>
      )}

      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/90 shadow-sm backdrop-blur">
        <div className="flex items-center justify-between border-b border-zinc-800 px-5 py-4">
          <h2 className="text-sm font-semibold text-zinc-100">
            Sent notifications <span className="font-mono text-xs text-zinc-500">({logs.length})</span>
          </h2>
          <button type="button" onClick={load}
            className="flex items-center gap-1.5 text-xs text-zinc-400 transition hover:text-red-400">
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center gap-2 px-5 py-10 text-sm text-zinc-500">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading notifications…
          </div>
        ) : logs.length === 0 ? (
          <div className="px-5 py-10 text-center text-sm text-zinc-500">
            No notifications yet. Register a notification email in Settings — high-severity
            events (quarantines, sender blocks, releases) will appear here.
          </div>
        ) : (
          <div className="divide-y divide-zinc-800">
            {logs.map((log) => (
              <div key={log.id} className="flex flex-col gap-2 px-5 py-3.5 lg:flex-row lg:items-center lg:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <Bell className="h-3.5 w-3.5 text-red-400" />
                    <span className="truncate text-sm font-semibold text-zinc-100">{log.subject}</span>
                    <span className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider ${STATUS_STYLES[log.status] ?? STATUS_STYLES.failed}`}>
                      {log.status}
                    </span>
                    <span className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-zinc-400">
                      {log.backend.replace('_', ' ')}
                    </span>
                  </div>
                  <p className="mt-1 font-mono text-[11px] text-zinc-500">
                    {log.event_type.replace(/_/g, ' ')} → {log.recipient_email} · {formatWhen(log.created_at)}
                  </p>
                  {log.error_detail && <p className="mt-1 text-xs text-red-400">{log.error_detail}</p>}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <p className="flex items-center gap-1.5 text-[11px] text-zinc-600">
        <Mail className="h-3 w-3" />
        System notifications are delivered by the DB-logged backend by default
        (rendered and persisted here) or via optional SMTP — and are never sent
        to a connected Gmail mailbox.
      </p>
    </div>
  );
}
