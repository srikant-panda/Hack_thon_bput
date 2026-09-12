import { useState } from 'react';
import { Ban, RefreshCw, ShieldBan } from 'lucide-react';
import * as api from '../services/api';
import { useApi } from '../hooks/useApi';
import { useUiStore } from '../store/uiStore';
import { useAuthStore } from '../store/authStore';
import type { ActionExecution } from '../types';
import PageHeader from '../components/common/PageHeader';
import SeverityBadge from '../components/common/SeverityBadge';
import DataTable, { type Column } from '../components/common/DataTable';
import EmptyState from '../components/common/EmptyState';
import { PanelSkeleton } from '../components/common/LoadingSkeleton';

function UnblockButton({ exec, onUnblock }: { exec: ActionExecution; onUnblock: (exec: ActionExecution) => void }) {
  const [confirming, setConfirming] = useState(false);
  if (!confirming) {
    return (
      <button
        onClick={() => setConfirming(true)}
        className="rounded-lg border border-zinc-700 px-2.5 py-1 text-[11px] font-semibold text-zinc-300 hover:border-red-500/60 hover:text-red-400 transition"
      >
        Unblock
      </button>
    );
  }
  return (
    <div className="flex items-center gap-1">
      <button
        onClick={() => onUnblock(exec)}
        className="rounded-lg bg-red-600 px-2 py-0.5 text-[11px] font-semibold text-white hover:bg-red-500 transition"
      >
        Confirm
      </button>
      <button
        onClick={() => setConfirming(false)}
        className="rounded-lg border border-zinc-700 px-2 py-0.5 text-[11px] text-zinc-400 hover:bg-zinc-800 transition"
      >
        Cancel
      </button>
    </div>
  );
}

export default function BlockList() {
  const addToast = useUiStore((s) => s.addToast);
  const can = useAuthStore((s) => s.can);
  const canUnblock = can('mutate'); // analyst and above

  const [page, setPage] = useState(1);
  const { data, loading, error, refetch } = useApi(() => api.listBlocklist(page, 20), [page]);

  const handleUnblock = async (exec: ActionExecution) => {
    try {
      await api.unblockItem(exec.id);
      addToast('Item removed from the block list', 'low');
      refetch();
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Unblock failed', 'high');
    }
  };

  const columns: Column<ActionExecution>[] = [
    { key: 'type', header: 'Action', render: (e) => <span className="font-mono text-xs text-red-400">{e.action_type}</span>, sortValue: (e) => e.action_type },
    {
      key: 'target',
      header: 'Target',
      render: (e) => {
        const t = e.target ?? {};
        const url = typeof t.url === 'string' ? t.url : null;
        const ip = typeof t.source_ip === 'string' ? t.source_ip : null;
        return url ? (
          <span className="line-clamp-1 max-w-sm font-mono text-xs text-zinc-300">{url}</span>
        ) : ip ? (
          <span className="rounded bg-zinc-900 px-1.5 py-0.5 font-mono text-xs text-zinc-200 ring-1 ring-zinc-700">{ip}</span>
        ) : (
          <span className="text-xs text-zinc-500">—</span>
        );
      },
    },
    { key: 'module', header: 'Module', render: (e) => <span className="text-xs text-zinc-400">{e.module}</span>, sortValue: (e) => e.module },
    { key: 'risk', header: 'Risk', render: (e) => <span className="font-mono font-semibold text-zinc-100">{e.risk_score}</span>, sortValue: (e) => e.risk_score },
    { key: 'severity', header: 'Severity', render: (e) => <SeverityBadge severity={e.severity} />, sortValue: (e) => e.severity },
    { key: 'blocked_at', header: 'Blocked At', render: (e) => <span className="text-xs text-zinc-500">{new Date(e.executed_at ?? e.created_at).toLocaleString()}</span>, sortValue: (e) => e.executed_at ?? e.created_at },
    {
      key: 'controls',
      header: '',
      render: (e) => (canUnblock ? <UnblockButton exec={e} onUnblock={handleUnblock} /> : null),
    },
  ];

  const totalPages = data ? Math.max(1, Math.ceil(data.total / (data.page_size || 20))) : 1;

  return (
    <div className="space-y-5">
      <PageHeader
        title="Block List"
        description="URLs and IPs currently blocked by enforcement actions. Unblocking restores access immediately."
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
        <PanelSkeleton height="h-72" />
      ) : error ? (
        <EmptyState icon={ShieldBan} title="Failed to load the block list" description={error} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          icon={Ban}
          title="Block list is empty"
          description="No URLs or IPs are currently blocked by enforcement actions."
        />
      ) : (
        <>
          <DataTable columns={columns} data={data.items} rowKey={(e) => e.id} emptyMessage="No blocked items" />
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
