import { useState } from 'react';
import { CheckCircle2, RefreshCw, ShieldCheck, XCircle } from 'lucide-react';
import * as api from '../services/api';
import { useApi } from '../hooks/useApi';
import { useUiStore } from '../store/uiStore';
import { useAuthStore } from '../store/authStore';
import type { ActionExecution } from '../types';
import PageHeader from '../components/common/PageHeader';
import SeverityBadge from '../components/common/SeverityBadge';
import EmptyState from '../components/common/EmptyState';
import DataTable, { type Column } from '../components/common/DataTable';
import { PanelSkeleton } from '../components/common/LoadingSkeleton';
import { MODULE_LABELS } from '../constants';

function targetSummary(exec: ActionExecution): string {
  const t = exec.target ?? {};
  if (t.subject) return `${t.sender ?? t.url ?? 'unknown'} → ${t.recipient ?? 'unknown'}`;
  if (t.url) return String(t.url);
  if (t.source_ip) return `${t.source_ip}${t.destination_ip ? ` → ${t.destination_ip}` : ''}`;
  if (t.user_id) return `user ${t.user_id}`;
  return Object.keys(t).length ? JSON.stringify(t).slice(0, 80) : '—';
}

export default function ApprovalQueue() {
  const addToast = useUiStore((s) => s.addToast);
  const can = useAuthStore((s) => s.can);
  const canDecide = can('mutate'); // analyst and above
  const [selected, setSelected] = useState<ActionExecution | null>(null);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);

  const { data, loading, error, refetch } = useApi(
    () => api.listActions({ status: 'pending', page_size: 100 }),
    []
  );

  const refresh = () => {
    refetch();
    setSelected(null);
    setReason('');
  };

  const handleApprove = async (exec: ActionExecution) => {
    setBusy(true);
    try {
      await api.approveAction(exec.id, 'Approved from the SOC console');
      addToast(`Action ${exec.action_type.replace(/_/g, ' ')} approved and executed`, 'low');
      refresh();
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Approval failed', 'high');
    } finally {
      setBusy(false);
    }
  };

  const handleReject = async (exec: ActionExecution) => {
    if (!reason.trim()) {
      addToast('A rejection reason is required', 'medium');
      return;
    }
    setBusy(true);
    try {
      await api.rejectAction(exec.id, reason.trim());
      addToast(`Action ${exec.action_type.replace(/_/g, ' ')} rejected`, 'low');
      refresh();
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Rejection failed', 'high');
    } finally {
      setBusy(false);
    }
  };

  const columns: Column<ActionExecution>[] = [
    { key: 'action', header: 'Action', render: (e) => <span className="font-mono text-xs text-red-400">{e.action_type}</span>, sortValue: (e) => e.action_type },
    { key: 'module', header: 'Module', render: (e) => <span className="text-xs text-zinc-400">{MODULE_LABELS[e.module as keyof typeof MODULE_LABELS] ?? e.module}</span>, sortValue: (e) => e.module },
    { key: 'target', header: 'Target', render: (e) => <span className="line-clamp-1 max-w-xs font-mono text-xs text-zinc-300">{targetSummary(e)}</span> },
    { key: 'risk', header: 'Risk', render: (e) => <span className="font-mono font-semibold text-zinc-100">{e.risk_score}</span>, sortValue: (e) => e.risk_score },
    { key: 'severity', header: 'Severity', render: (e) => <SeverityBadge severity={e.severity} />, sortValue: (e) => e.severity },
    { key: 'age', header: 'Waiting Since', render: (e) => <span className="text-xs text-zinc-500">{new Date(e.created_at).toLocaleString()}</span>, sortValue: (e) => e.created_at },
  ];

  return (
    <div className="space-y-5">
      <PageHeader
        title="Approval Queue"
        description="Enforcement actions awaiting analyst review. Approving executes the action immediately; rejecting dismisses it with a reason."
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
        <EmptyState icon={XCircle} title="Failed to load the approval queue" description={error} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          icon={CheckCircle2}
          title="No pending approvals"
          description="Automated enforcement decisions are handling everything, or no actions above the approval threshold have fired yet."
        />
      ) : (
        <>
          <DataTable
            columns={columns}
            data={data.items}
            rowKey={(e) => e.id}
            onRowClick={(e) => {
              setSelected(selected?.id === e.id ? null : e);
              setReason('');
            }}
            emptyMessage="No pending approvals"
          />

          {selected && (
            <div className="rounded-xl border border-zinc-700/50 bg-zinc-800/60 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-red-400" />
                  <h3 className="font-mono text-sm font-semibold text-zinc-100">{selected.action_type}</h3>
                  <SeverityBadge severity={selected.severity} />
                </div>
                <span className="font-mono text-[11px] text-zinc-500">
                  alert {selected.alert_id ?? '—'} · policy {selected.policy_id ?? '—'}
                </span>
              </div>

              <div className="mt-3 grid gap-3 text-xs md:grid-cols-2">
                <div>
                  <p className="font-semibold uppercase tracking-wider text-zinc-500">Target</p>
                  <pre className="mt-1 overflow-x-auto rounded-lg bg-zinc-900 p-2 font-mono text-[11px] text-zinc-300">
                    {JSON.stringify(selected.target ?? {}, null, 2)}
                  </pre>
                </div>
                <div>
                  <p className="font-semibold uppercase tracking-wider text-zinc-500">Context</p>
                  <dl className="mt-1 space-y-1 text-zinc-300">
                    <div className="flex justify-between gap-3"><dt className="text-zinc-500">Risk score</dt><dd className="font-mono">{selected.risk_score}</dd></div>
                    <div className="flex justify-between gap-3"><dt className="text-zinc-500">Module</dt><dd>{MODULE_LABELS[selected.module as keyof typeof MODULE_LABELS] ?? selected.module}</dd></div>
                    <div className="flex justify-between gap-3"><dt className="text-zinc-500">Triggered by</dt><dd className="font-mono text-[11px]">{selected.triggered_by}{selected.triggered_by_id ? ` (${selected.triggered_by_id})` : ''}</dd></div>
                    <div className="flex justify-between gap-3"><dt className="text-zinc-500">Execution mode</dt><dd>{selected.execution_mode}</dd></div>
                  </dl>
                </div>
              </div>

              {canDecide ? (
                <div className="mt-4 flex flex-wrap items-center gap-2">
                  <button
                    disabled={busy}
                    onClick={() => handleApprove(selected)}
                    className="flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-500 disabled:opacity-50 transition"
                  >
                    <CheckCircle2 className="h-3.5 w-3.5" /> Approve &amp; Execute
                  </button>
                  <input
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    placeholder="Rejection reason (required)"
                    className="min-w-52 flex-1 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-xs text-zinc-200 placeholder-zinc-600 outline-none focus:border-red-500/60"
                  />
                  <button
                    disabled={busy || !reason.trim()}
                    onClick={() => handleReject(selected)}
                    className="flex items-center gap-1.5 rounded-lg bg-red-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-red-500 disabled:opacity-50 transition"
                  >
                    <XCircle className="h-3.5 w-3.5" /> Reject
                  </button>
                </div>
              ) : (
                <p className="mt-3 text-xs text-zinc-500">Your role is read-only — ask an analyst or admin to decide this action.</p>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
