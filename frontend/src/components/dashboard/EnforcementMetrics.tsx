import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Ban, ClipboardCheck, PackageOpen, Zap } from 'lucide-react';
import * as api from '../../services/api';
import { useApi } from '../../hooks/useApi';
import StatCard from '../common/StatCard';
import ChartCard from '../common/ChartCard';
import { PanelSkeleton } from '../common/LoadingSkeleton';

const tooltipStyle = {
  backgroundColor: '#101010',
  border: '1px solid #262626',
  borderRadius: '8px',
  fontSize: '12px',
  color: '#fafafa',
};

interface Metrics {
  autoExecuted: number;
  pending: number;
  quarantined: number;
  blocked: number;
  byActionType: { action: string; count: number }[];
}

async function fetchEnforcementMetrics(): Promise<Metrics> {
  const [successTotal, pending, quarantined, blocked, successItems] = await Promise.all([
    api.listActions({ status: 'success', page_size: 1 }),
    api.listActions({ status: 'pending', page_size: 1 }),
    api.listQuarantine(1, 1),
    api.listBlocklist(1, 1),
    api.listActions({ status: 'success', page_size: 100 }),
  ]);

  const counts = new Map<string, number>();
  for (const item of successItems.items) {
    counts.set(item.action_type, (counts.get(item.action_type) ?? 0) + 1);
  }
  const byActionType = [...counts.entries()]
    .map(([action, count]) => ({ action, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  return {
    autoExecuted: successTotal.total,
    pending: pending.total,
    quarantined: quarantined.total,
    blocked: blocked.total,
    byActionType,
  };
}

export default function EnforcementMetrics() {
  const { data, loading, error } = useApi(fetchEnforcementMetrics, []);

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <PanelSkeleton key={i} height="h-24" />
          ))}
        </div>
        <PanelSkeleton height="h-56" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="rounded-xl border border-zinc-700/50 bg-zinc-800/60 p-4 text-xs text-zinc-500">
        Enforcement metrics unavailable: {error ?? 'no data'}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatCard title="Auto-Executed" value={data.autoExecuted} icon={Zap} trend="up" trendValue="server mode" color="#dc2626" />
        <StatCard title="Pending Approval" value={data.pending} icon={ClipboardCheck} trend="neutral" trendValue="awaiting review" color="#f87171" />
        <StatCard title="Quarantined" value={data.quarantined} icon={PackageOpen} trend="up" trendValue="held items" color="#ef4444" />
        <StatCard title="Blocked URLs/IPs" value={data.blocked} icon={Ban} trend="up" trendValue="active blocks" color="#7f1d1d" />
      </div>

      <ChartCard title="Enforcement by Action Type" subtitle="Successful server-mode enforcement actions">
        {data.byActionType.length === 0 ? (
          <p className="py-10 text-center text-xs text-zinc-500">No enforcement actions executed yet.</p>
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={data.byActionType} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
              <CartesianGrid stroke="#262626" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="action" tick={{ fill: '#a3a3a3', fontSize: 10 }} interval={0} angle={-18} textAnchor="end" height={50} />
              <YAxis tick={{ fill: '#a3a3a3', fontSize: 10 }} allowDecimals={false} />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: '#26262655' }} />
              <Bar dataKey="count" fill="#dc2626" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </ChartCard>
    </div>
  );
}
