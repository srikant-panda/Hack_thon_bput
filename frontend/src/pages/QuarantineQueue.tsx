import { useState } from 'react';
import { AlertTriangle, Archive, PackageOpen, RefreshCw } from 'lucide-react';
import * as api from '../services/api';
import { useApi } from '../hooks/useApi';
import { useUiStore } from '../store/uiStore';
import { useAuthStore } from '../store/authStore';
import type { ActionExecution } from '../types';
import PageHeader from '../components/common/PageHeader';
import SeverityBadge from '../components/common/SeverityBadge';
import StatusPill from '../components/common/StatusPill';
import EmptyState from '../components/common/EmptyState';
import { PanelSkeleton } from '../components/common/LoadingSkeleton';

function QuarantineCard({
  exec,
  canRelease,
  onRelease,
}: {
  exec: ActionExecution;
  canRelease: boolean;
  onRelease: (exec: ActionExecution) => void;
}) {
  const t = exec.target ?? {};
  const sender = typeof t.sender === 'string' ? t.sender : null;
  const recipient = typeof t.recipient === 'string' ? t.recipient : null;
  const subject = typeof t.subject === 'string' ? t.subject : null;
  const mediaType = typeof t.media_type === 'string' ? t.media_type : null;

  return (
    <div className="rounded-xl border border-zinc-700/50 bg-zinc-800/60 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <Archive className="h-4 w-4 text-red-400" />
          <h3 className="max-w-md truncate text-sm font-semibold text-zinc-100">
            {subject ?? (typeof t.url === 'string' ? t.url : exec.action_type)}
          </h3>
        </div>
        <div className="flex items-center gap-2">
          <SeverityBadge severity={exec.severity} />
          <span className="font-mono text-[11px] text-zinc-500">risk {exec.risk_score}</span>
        </div>
      </div>

      <dl className="mt-2 grid gap-x-4 gap-y-1 text-xs sm:grid-cols-2">
        {sender && (
          <div className="flex gap-2">
            <dt className="shrink-0 text-zinc-500">Sender</dt>
            <dd className="truncate font-mono text-zinc-300">{sender}</dd>
          </div>
        )}
        {recipient && (
          <div className="flex gap-2">
            <dt className="shrink-0 text-zinc-500">Recipient</dt>
            <dd className="truncate font-mono text-zinc-300">{recipient}</dd>
          </div>
        )}
        {mediaType && (
          <div className="flex gap-2">
            <dt className="shrink-0 text-zinc-500">Media</dt>
            <dd className="font-mono text-zinc-300">{mediaType}</dd>
          </div>
        )}
        <div className="flex gap-2">
          <dt className="shrink-0 text-zinc-500">Quarantined</dt>
          <dd className="font-mono text-zinc-400">{new Date(exec.executed_at ?? exec.created_at).toLocaleString()}</dd>
        </div>
      </dl>

      <div className="mt-3 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <StatusPill status={exec.status} />
          {exec.alert_id && (
            <span className="font-mono text-[11px] text-zinc-600">alert {exec.alert_id}</span>
          )}
        </div>
        {canRelease && (
          <ReleaseButton exec={exec} onRelease={onRelease} />
        )}
      </div>
    </div>
  );
}

function ReleaseButton({ exec, onRelease }: { exec: ActionExecution; onRelease: (exec: ActionExecution) => void }) {
  const [confirming, setConfirming] = useState(false);
  if (!confirming) {
    return (
      <button
        onClick={() => setConfirming(true)}
        className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs font-semibold text-zinc-300 hover:border-red-500/60 hover:text-red-400 transition"
      >
        Release
      </button>
    );
  }
  return (
    <div className="flex items-center gap-1.5">
      <span className="flex items-center gap-1 text-[11px] text-amber-400">
        <AlertTriangle className="h-3 w-3" /> Deliver to recipient?
      </span>
      <button
        onClick={() => onRelease(exec)}
        className="rounded-lg bg-red-600 px-2.5 py-1 text-[11px] font-semibold text-white hover:bg-red-500 transition"
      >
        Confirm
      </button>
      <button
        onClick={() => setConfirming(false)}
        className="rounded-lg border border-zinc-700 px-2.5 py-1 text-[11px] text-zinc-400 hover:bg-zinc-800 transition"
      >
        Cancel
      </button>
    </div>
  );
}

export default function QuarantineQueue() {
  const addToast = useUiStore((s) => s.addToast);
  const can = useAuthStore((s) => s.can);
  const canRelease = can('mutate'); // analyst and above

  const [page, setPage] = useState(1);
  const { data, loading, error, refetch } = useApi(
    () => api.listQuarantine(page, 12),
    [page]
  );

  const handleRelease = async (exec: ActionExecution) => {
    try {
      await api.releaseQuarantine(exec.id);
      addToast('Item released from quarantine', 'low');
      refetch();
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Release failed', 'high');
    }
  };

  const totalPages = data ? Math.max(1, Math.ceil(data.total / (data.page_size || 12))) : 1;

  return (
    <div className="space-y-5">
      <PageHeader
        title="Quarantine Queue"
        description="Items held out of user reach by enforcement actions. Releasing delivers the item back to its recipient."
        actions={
          <button
            onClick={refetch}
            className="flex items-center gap-1.5 rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800 transition"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        }
      />

      {loading ? (
        <div className="grid gap-4 md:grid-cols-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <PanelSkeleton key={i} height="h-36" />
          ))}
        </div>
      ) : error ? (
        <EmptyState icon={PackageOpen} title="Failed to load quarantine queue" description={error} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          icon={PackageOpen}
          title="Quarantine is empty"
          description="No items are currently held by enforcement actions."
        />
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-2">
            {data.items.map((exec) => (
              <QuarantineCard key={exec.id} exec={exec} canRelease={canRelease} onRelease={handleRelease} />
            ))}
          </div>
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-3 text-xs text-zinc-400">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="rounded-lg border border-zinc-700 px-3 py-1.5 hover:bg-zinc-800 disabled:opacity-40 transition"
              >
                Previous
              </button>
              <span className="font-mono">
                page {data?.page ?? page} / {totalPages} · {data?.total ?? 0} items
              </span>
              <button
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
                className="rounded-lg border border-zinc-700 px-3 py-1.5 hover:bg-zinc-800 disabled:opacity-40 transition"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
