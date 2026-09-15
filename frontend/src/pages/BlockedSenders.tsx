import { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  Ban,
  Clock,
  Eye,
  Folder,
  Loader2,
  RefreshCw,
  Search,
  ShieldCheck,
  ShieldOff,
  X,
} from 'lucide-react';
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
  const [notice, setNotice] = useState<string | null>(null);
  // Search (sender email / event-time range) + dismissal + preview — F2/F4.
  const [searchSender, setSearchSender] = useState('');
  const [searchFrom, setSearchFrom] = useState('');
  const [searchTo, setSearchTo] = useState('');
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const [preview, setPreview] = useState<BlockedSender | null>(null);
  const [collapsedFolders, setCollapsedFolders] = useState<Set<string>>(new Set());

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

  // Two-action honesty (D1): "Trust sender" never removes an active filter.
  // Unblocking remains a separate explicit button on this page.
  const handleTrust = async (block: BlockedSender) => {
    setActionId(block.id);
    setError(null);
    setNotice(null);
    try {
      await api.trustSender(block.sender_email, 'trusted from Blocked Senders page');
      setNotice(
        `${block.sender_email} added to your trust list — future auto-enforcement for this sender is recommend-only. The Gmail filter stays active until you unblock it explicitly.`,
      );
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Trust failed');
    } finally {
      setActionId(null);
    }
  };

  const matchesSearch = (b: BlockedSender) => {
    if (searchSender && !b.sender_email.toLowerCase().includes(searchSender.toLowerCase())) return false;
    const when = b.blocked_at ? new Date(b.blocked_at).getTime() : null;
    if (searchFrom && (when === null || when < new Date(searchFrom).getTime())) return false;
    if (searchTo && (when === null || when > new Date(searchTo).getTime() + 86_399_000)) return false;
    return true;
  };
  const visible = blocks.filter((b) => !dismissed.has(b.id));
  const activeBlocks = visible.filter((b) => b.status === 'blocked' && matchesSearch(b));
  const pastBlocks = visible.filter((b) => b.status !== 'blocked' && matchesSearch(b));
  const allVisible = [...activeBlocks, ...pastBlocks];
  const providerLabel = (pv: string | null | undefined) =>
    !pv ? 'Other mailboxes' : pv === 'gmail' ? 'Gmail' : pv === 'outlook' ? 'Outlook' : pv.charAt(0).toUpperCase() + pv.slice(1);
  const groupedFolders = Array.from(
    new Set(allVisible.map((b) => providerLabel(b.provider))),
  ).map((label) => {
    const items = allVisible.filter((b) => providerLabel(b.provider) === label);
    return { label, items, count: items.length, active: items.filter((b) => b.status === 'blocked').length };
  });
  const toggleFolder = (label: string) =>
    setCollapsedFolders((prev) => {
      const next = new Set(prev);
      if (next.has(label)) next.delete(label);
      else next.add(label);
      return next;
    });
  const dismiss = (id: string) =>
    setDismissed((prev) => {
      const next = new Set(prev);
      next.add(id);
      return next;
    });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Blocked Senders"
        description="Senders auto-blocked via Gmail filters after high or critical verdicts. Temporary blocks expire automatically and their filters are removed by the scheduler. Trusting a sender makes future enforcement recommend-only — it never removes the active filter; use Unblock for that."
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
      {notice && (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3.5 py-2.5 text-sm text-emerald-300">
          <ShieldCheck className="h-4 w-4 text-emerald-400" />
          {notice}
        </div>
      )}

      {/* Search: sender email / event-time range (F4) */}
      <div className="flex flex-wrap items-center gap-3 rounded-2xl border border-zinc-800 bg-zinc-900/90 px-5 py-3.5 shadow-sm backdrop-blur">
        <Search className="h-4 w-4 text-zinc-500" />
        <input
          type="text"
          value={searchSender}
          onChange={(e) => setSearchSender(e.target.value)}
          placeholder="Sender email…"
          className="w-60 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-1.5 text-xs text-zinc-100 placeholder-zinc-600 outline-none focus:border-red-500/60"
        />
        <label className="text-[10px] uppercase tracking-wider text-zinc-500">Blocked from</label>
        <input type="date" value={searchFrom} onChange={(e) => setSearchFrom(e.target.value)}
          className="rounded-lg border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 text-xs text-zinc-200 outline-none focus:border-red-500/60" />
        <label className="text-[10px] uppercase tracking-wider text-zinc-500">To</label>
        <input type="date" value={searchTo} onChange={(e) => setSearchTo(e.target.value)}
          className="rounded-lg border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 text-xs text-zinc-200 outline-none focus:border-red-500/60" />
        {(searchSender || searchFrom || searchTo) !== '' && (
          <button
            type="button"
            onClick={() => { setSearchSender(''); setSearchFrom(''); setSearchTo(''); }}
            className="ml-auto inline-flex items-center gap-1 text-[11px] text-zinc-400 transition hover:text-zinc-200"
          >
            <X className="h-3 w-3" /> Clear
          </button>
        )}
      </div>

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
        ) : visible.length === 0 ? (
          <div className="px-5 py-10 text-center text-sm text-zinc-500">
            No senders blocked yet. High and critical scan verdicts auto-block their sender via a
            Gmail filter that sends future mail straight to trash when auto-enforcement is on.
          </div>
        ) : allVisible.length === 0 ? (
          <div className="px-5 py-10 text-center text-sm text-zinc-500">No entries match the search.</div>
        ) : (
          <div className="divide-y divide-zinc-800">
            {groupedFolders.map((folder) => (
              <div key={folder.label}>
                <button
                  type="button"
                  onClick={() => toggleFolder(folder.label)}
                  className="flex w-full items-center gap-2.5 bg-zinc-950/60 px-5 py-2.5 text-left transition hover:bg-zinc-900"
                >
                  <Folder className="h-4 w-4 text-red-400" />
                  <span className="text-xs font-bold text-zinc-100">{folder.label}</span>
                  <span className="font-mono text-[10px] text-zinc-500">
                    {folder.count} sender{folder.count === 1 ? '' : 's'} · {folder.active} blocked
                  </span>
                </button>
                {!collapsedFolders.has(folder.label) && folder.items.map((block) => (
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
                  <button
                    type="button"
                    onClick={() => setPreview(block)}
                    title="Preview block details"
                    className="flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-1.5 text-xs font-semibold text-zinc-200 transition hover:border-zinc-700 hover:bg-zinc-800/60"
                  >
                    <Eye className="h-3.5 w-3.5" />
                    Preview
                  </button>
                  {block.status !== 'blocked' && (
                    <button
                      type="button"
                      onClick={() => dismiss(block.id)}
                      title="Remove this resolved entry from the list"
                      className="flex items-center gap-1 rounded-lg border border-zinc-700 bg-zinc-900 px-2.5 py-1.5 text-xs text-zinc-400 transition hover:border-red-500/40 hover:text-red-400"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  )}
                  {block.status === 'blocked' && (
                    <>
                      <button
                        type="button"
                        onClick={() => handleTrust(block)}
                        disabled={actionId === block.id || isMockMode}
                        className="flex items-center gap-1.5 rounded-lg border border-sky-500/30 bg-sky-500/10 px-3 py-1.5 text-xs font-semibold text-sky-400 transition hover:bg-sky-500/20 disabled:opacity-50"
                      >
                        {actionId === block.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                        Trust Sender
                      </button>
                      <button
                        type="button"
                        onClick={() => handleUnblock(block)}
                        disabled={actionId === block.id || isMockMode}
                        className="flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-400 transition hover:bg-emerald-500/20 disabled:opacity-50"
                      >
                        {actionId === block.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldOff className="h-3.5 w-3.5" />}
                        Unblock Sender
                      </button>
                    </>
                  )}
                </div>
              </div>
                ))}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Preview drawer — block details (F2) */}
      {preview && (
        <div className="fixed inset-0 z-50 flex items-stretch justify-end bg-black/70 backdrop-blur-sm" onClick={() => setPreview(null)}>
          <div
            className="h-full w-full max-w-xl overflow-y-auto border-l border-zinc-800 bg-zinc-950 p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-start justify-between gap-3">
              <div>
                <h3 className="flex items-center gap-2 text-base font-bold text-zinc-100">
                  <Ban className="h-5 w-5 text-red-400" /> {preview.sender_email}
                </h3>
                <p className="mt-0.5 font-mono text-xs text-zinc-500">
                  {providerLabel(preview.provider)} · filter {preview.provider_rule_id ?? 'none'}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setPreview(null)}
                className="rounded-lg border border-zinc-800 bg-zinc-900 p-1.5 text-zinc-400 transition hover:text-red-400"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="mb-4 flex flex-wrap items-center gap-2">
              <span className={`rounded px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${STATUS_STYLES[preview.status] ?? STATUS_STYLES.expired}`}>
                {preview.status}
              </span>
              {preview.expires_at && (
                <span className="inline-flex items-center gap-1 rounded bg-zinc-800 px-2 py-0.5 font-mono text-[10px] text-zinc-300">
                  <Clock className="h-3 w-3" /> expires {formatWhen(preview.expires_at)}
                </span>
              )}
            </div>

            <div className="space-y-3 text-xs leading-relaxed text-zinc-300">
              <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
                <h4 className="mb-2 font-mono text-[11px] font-bold uppercase tracking-wider text-zinc-400">What blocking means here</h4>
                <p>
                  An active Gmail filter (criteria: <span className="font-mono text-zinc-100">from: {preview.sender_email}</span>)
                  removes future mail from this sender from the inbox and sends it straight to{' '}
                  <span className="font-mono text-red-300">TRASH</span>, keeping the blocked label for traceability.
                  It acts server-side in Gmail — nothing arrives in the inbox while it is active.
                </p>
              </div>
              <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
                <h4 className="mb-2 font-mono text-[11px] font-bold uppercase tracking-wider text-zinc-400">Block record</h4>
                <p><span className="text-zinc-500">Reason:</span> {preview.reason}</p>
                <p><span className="text-zinc-500">Blocked at:</span> {formatWhen(preview.blocked_at)}</p>
                <p><span className="text-zinc-500">Expires:</span> {preview.expires_at ? formatWhen(preview.expires_at) : 'manual'}</p>
                <p><span className="text-zinc-500">Gmail filter id:</span> <span className="font-mono">{preview.provider_rule_id ?? '— (no filter was created)'}</span></p>
                {preview.last_error && <p className="text-red-400">Last error: {preview.last_error}</p>}
              </div>
              <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 text-amber-300">
                Trusting this sender only makes future auto-enforcement recommend-only — the Gmail
                filter keeps working until you press <strong>Unblock Sender</strong> (explicit two-step, FP-hardening D1).
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
