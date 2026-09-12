import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Ban, Clock, Loader2, RefreshCw, ShieldOff } from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import * as api from '../services/api';
import type { BlockedSender } from '../types';

const STATUS_STYLES: Record<string, string> = {
  blocked: 'bg-red-500/10 text-red-400 ring-1 ring-red-500/30',
  released: 'bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/30',
  expired: 'bg-zinc-800 text-zinc-400 ring-1 ring-zinc-700',
};

function formatWhen(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

export default function BlockedSenders() {
  const isMockMode = api.isMockMode();
  const [blocks, setBlocks] = useState<BlockedSender[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionId, setActionId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setBlocks(await api.listBlockedSenders());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load blocked senders');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleUnblock = async (block: BlockedSender) => {
    setActionId(block.id);
    setError(null);
    try {
      await api.unblockSender(block.id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unblock failed');
    } finally {
      setActionId(null);
    }
  };

  const activeBlocks = blocks.filter((b) => b.status === 'blocked');
  const pastBlocks = blocks.filter((b) => b.status !== 'blocked');

  return (
    <div className="space-y-6">
      <PageHeader
        title="Blocked Senders"
        description="Senders auto-blocked via Gmail filters after high or critical verdicts. Temporary blocks expire automatically and their filters are removed by the scheduler."
      />

      {isMockMode && (
        <div className="flex items-center gap-2 rounded-lg border border-zinc-700/60 bg-zinc-800/40 px-3.5 py-2.5 text-xs text-zinc-300">
          <AlertTriangle className="h-4 w-4 text-amber-400" />
          <span className="font-mono font-bold tracking-wider">DEMO MODE — enforcement actions are simulated/unavailable</span>
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
            Blocked senders{' '}
            <span className="font-mono text-xs text-zinc-500">({activeBlocks.length} active)</span>
          </h2>
          <button
            type="button"
            onClick={load}
            className="flex items-center gap-1.5 text-xs text-zinc-400 transition hover:text-red-400"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center gap-2 px-5 py-10 text-sm text-zinc-500">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading blocked senders…
          </div>
        ) : blocks.length === 0 ? (
          <div className="px-5 py-10 text-center text-sm text-zinc-500">
            No senders blocked yet. High and critical scan verdicts auto-block their sender via a
            Gmail filter when auto-enforcement is on.
          </div>
        ) : (
          <div className="divide-y divide-zinc-800">
            {[...activeBlocks, ...pastBlocks].map((block) => (
              <div key={block.id} className="flex flex-col gap-3 px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <Ban className="h-3.5 w-3.5 text-red-400" />
                    <span className="truncate text-sm font-semibold text-zinc-100">{block.sender_email}</span>
                    <span className={`rounded px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${STATUS_STYLES[block.status] ?? STATUS_STYLES.expired}`}>
                      {block.status}
                    </span>
                  </div>
                  <p className="mt-1 font-mono text-[11px] text-zinc-500">
                    {block.reason} · blocked {formatWhen(block.blocked_at)} · expires{' '}
                    {block.expires_at ? (
                      <span className="inline-flex items-center gap-1">
                        <Clock className="h-3 w-3" /> {formatWhen(block.expires_at)}
                      </span>
                    ) : (
                      'manual'
                    )}
                    {block.provider_rule_id ? ` · filter ${block.provider_rule_id}` : ' · no filter created'}
                  </p>
                  {block.last_error && <p className="mt-1 text-xs text-red-400">Last error: {block.last_error}</p>}
                </div>
                <div className="flex flex-shrink-0 items-center gap-2">
                  {block.status === 'blocked' && (
                    <button
                      type="button"
                      onClick={() => handleUnblock(block)}
                      disabled={actionId === block.id || isMockMode}
                      className="flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-400 transition hover:bg-emerald-500/20 disabled:opacity-50"
                    >
                      {actionId === block.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldOff className="h-3.5 w-3.5" />}
                      Unblock Sender
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
