import { useCallback, useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { ChevronDown, Loader2, RefreshCw } from 'lucide-react';
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

const FEATURE_LABELS: Record<orgApi.DashboardFeature, string> = {
  phishing: 'Phishing Scans',
  url: 'URL Scans',
  deepfake: 'Deepfake Scans',
  impersonation: 'Impersonation Scans',
};

const PAGE_SIZE = 25;

/**
 * ORG-2: reusable verbose per-feature dashboard (phishing | url | deepfake |
 * impersonation). Table + filters + detail drawer; new scans appear via
 * Supabase postgres_changes on org alerts.
 */
export default function OrgFeatureDashboard() {
  const { orgId, feature } = useParams<{ orgId: string; feature: string }>();
  const addToast = useUiStore((s) => s.addToast);
  const feat = (feature ?? 'phishing') as orgApi.DashboardFeature;

  const [data, setData] = useState<orgApi.FeatureDashboard | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const [severity, setSeverity] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [selected, setSelected] = useState<orgApi.FeatureScanRow | null>(null);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      setData(
        await orgApi.getFeatureDashboard(orgId, feat, {
          limit: PAGE_SIZE,
          offset: page * PAGE_SIZE,
          severity: severity || null,
          from_date: fromDate ? new Date(fromDate).toISOString() : null,
          to_date: toDate ? new Date(toDate).toISOString() : null,
        }),
      );
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to load scan feed', 'high');
    } finally {
      setLoading(false);
    }
  }, [orgId, feat, page, severity, fromDate, toDate, addToast]);

  useEffect(() => {
    load();
  }, [load]);

  useOrgRealtime('alerts', orgId, () => {
    if (page === 0) load();
  });

  if (!orgId) return <div className="p-6 text-sm text-zinc-400">No organization selected.</div>;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <PageHeader
          title={FEATURE_LABELS[feat] ?? 'Scans'}
          description="Verbose, org-scoped scan results fed by the gateway and mail streams."
        />
        <button
          onClick={load}
          className="inline-flex items-center gap-2 self-start rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-200 transition hover:border-zinc-500"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-zinc-800 bg-zinc-900/90 p-4 backdrop-blur">
        <select
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            setPage(0);
          }}
          className="rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-500/60"
        >
          <option value="">All severities</option>
          {['critical', 'high', 'medium', 'low', 'safe'].map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <label className="text-[11px] text-zinc-500">From</label>
        <input
          type="date"
          value={fromDate}
          onChange={(e) => {
            setFromDate(e.target.value);
            setPage(0);
          }}
          className="rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-500/60"
        />
        <label className="text-[11px] text-zinc-500">To</label>
        <input
          type="date"
          value={toDate}
          onChange={(e) => {
            setToDate(e.target.value);
            setPage(0);
          }}
          className="rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-500/60"
        />
        <span className="ml-auto font-mono text-[11px] text-zinc-500">
          {data ? `${data.total} total` : ''}
        </span>
      </div>

      {/* Feed table */}
      <div className="overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-900/90 backdrop-blur">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-zinc-800 font-mono uppercase tracking-wider text-zinc-500">
            <tr>
              <th className="px-4 py-3">Timestamp</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Score</th>
              <th className="px-4 py-3">Target / Title</th>
              <th className="px-4 py-3">Action Taken</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/70">
            {loading && (
              <tr><td colSpan={6} className="px-4 py-6 text-zinc-500"><Loader2 className="mr-2 inline h-4 w-4 animate-spin" />Loading…</td></tr>
            )}
            {!loading && data?.rows.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-6 text-zinc-500">No scans yet — feed this feature via the org gateway.</td></tr>
            )}
            {!loading &&
              data?.rows.map((row) => (
                <tr
                  key={row.alert_id}
                  onClick={() => setSelected(row)}
                  className="cursor-pointer text-zinc-300 transition hover:bg-zinc-800/40"
                >
                  <td className="px-4 py-3 font-mono text-zinc-500">
                    {row.timestamp ? new Date(row.timestamp).toLocaleString() : '—'}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ring-1 ${SEVERITY_STYLES[row.severity] ?? SEVERITY_STYLES.low}`}>
                      {row.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-zinc-200">{row.score}</td>
                  <td className="max-w-xs truncate px-4 py-3 text-zinc-200">{row.target ? `${row.target} — ` : ''}{row.title}</td>
                  <td className="px-4 py-3 font-mono text-zinc-400">{row.action_taken ?? '—'}</td>
                  <td className="px-4 py-3 text-right"><ChevronDown className="ml-auto h-4 w-4 rotate-[-90deg] text-zinc-600" /></td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {data && data.total > PAGE_SIZE && (
        <div className="flex items-center justify-end gap-3 text-xs text-zinc-400">
          <button
            disabled={page === 0}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            className="rounded border border-zinc-700 px-3 py-1.5 disabled:opacity-40"
          >
            Prev
          </button>
          <span className="font-mono">
            page {page + 1} / {Math.ceil(data.total / PAGE_SIZE)}
          </span>
          <button
            disabled={(page + 1) * PAGE_SIZE >= data.total}
            onClick={() => setPage((p) => p + 1)}
            className="rounded border border-zinc-700 px-3 py-1.5 disabled:opacity-40"
          >
            Next
          </button>
        </div>
      )}

      {/* Detail drawer */}
      {selected && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/70" onClick={() => setSelected(null)}>
          <div
            className="h-full w-full max-w-xl overflow-y-auto border-l border-zinc-800 bg-zinc-900 p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-sm font-bold text-zinc-100">Scan Detail</h3>
              <button onClick={() => setSelected(null)} className="text-xs text-zinc-400 hover:text-zinc-200">Close</button>
            </div>
            <div className="mb-4 flex items-center gap-3">
              <span className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ring-1 ${SEVERITY_STYLES[selected.severity] ?? ''}`}>
                {selected.severity}
              </span>
              <span className="font-mono text-xs text-zinc-400">score {selected.score}</span>
              {selected.action_taken && (
                <span className="rounded bg-zinc-800 px-2 py-0.5 font-mono text-[10px] text-zinc-300">{selected.action_taken}</span>
              )}
            </div>
            <h4 className="text-sm font-semibold text-zinc-100">{selected.title}</h4>
            {selected.target && <p className="mt-1 break-all font-mono text-xs text-zinc-400">{selected.target}</p>}
            {selected.explanation && (
              <p className="mt-4 rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 text-xs leading-relaxed text-zinc-300">
                {selected.explanation}
              </p>
            )}
            <h4 className="mt-5 font-mono text-[11px] uppercase tracking-wider text-zinc-500">Indicators ({selected.indicators.length})</h4>
            <ul className="mt-2 space-y-2">
              {selected.indicators.map((ind, i) => {
                const item = ind as Record<string, string>;
                return (
                  <li key={i} className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 text-xs">
                    <span className="font-mono text-[10px] uppercase text-red-400">{item.type}</span>
                    <span className={`ml-2 rounded px-1.5 py-0.5 text-[10px] uppercase ${SEVERITY_STYLES[item.severity] ?? ''}`}>{item.severity}</span>
                    <p className="mt-1 break-all font-mono text-zinc-300">{item.value}</p>
                    <p className="mt-1 text-zinc-500">{item.description}</p>
                  </li>
                );
              })}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
