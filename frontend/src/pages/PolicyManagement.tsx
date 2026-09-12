import { useState } from 'react';
import { ChevronDown, Save, Settings2, ShieldCheck, Zap } from 'lucide-react';
import * as api from '../services/api';
import { useApi } from '../hooks/useApi';
import { useUiStore } from '../store/uiStore';
import { useAuthStore } from '../store/authStore';
import type { EnforcementPolicy, PolicyUpdatePayload } from '../types';
import PageHeader from '../components/common/PageHeader';
import EmptyState from '../components/common/EmptyState';
import { PanelSkeleton } from '../components/common/LoadingSkeleton';

const ACTION_OPTIONS = [
  'block_and_quarantine',
  'block',
  'warn_and_log',
  'tag_and_warn',
  'allow',
  'rate_limit',
  'require_mfa',
  'revoke_session',
  'flag_for_review',
];

const MODULES: { key: string; label: string; high: keyof PolicyUpdatePayload; medium: keyof PolicyUpdatePayload }[] = [
  { key: 'phishing', label: 'Phishing', high: 'phishing_high_threshold', medium: 'phishing_medium_threshold' },
  { key: 'deepfake', label: 'Deepfake / Media', high: 'deepfake_high_threshold', medium: 'deepfake_medium_threshold' },
  { key: 'ato', label: 'Account Takeover', high: 'ato_high_threshold', medium: 'ato_medium_threshold' },
  { key: 'network', label: 'Network / API', high: 'network_high_threshold', medium: 'network_medium_threshold' },
  { key: 'impersonation', label: 'Impersonation / BEC', high: 'impersonation_high_threshold', medium: 'impersonation_medium_threshold' },
];

type Draft = Record<string, string | number | boolean>;

function toDraft(p: EnforcementPolicy): Draft {
  return { ...p } as Draft;
}

function Toggle({
  label,
  checked,
  onChange,
  disabled,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <label className={`flex cursor-pointer items-center justify-between gap-3 rounded-lg border border-zinc-700/60 bg-zinc-900/60 px-3 py-2 text-xs ${disabled ? 'opacity-60' : 'hover:border-zinc-600'}`}>
      <span className="text-zinc-300">{label}</span>
      <button
        type="button"
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`relative h-5 w-9 shrink-0 rounded-full transition ${checked ? 'bg-red-600' : 'bg-zinc-700'}`}
      >
        <span
          className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all ${checked ? 'left-[18px]' : 'left-0.5'}`}
        />
      </button>
    </label>
  );
}

function ThresholdSlider({
  label,
  value,
  onChange,
  disabled,
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
  disabled?: boolean;
}) {
  return (
    <div className="rounded-lg border border-zinc-700/60 bg-zinc-900/60 px-3 py-2">
      <div className="flex items-center justify-between text-xs">
        <span className="text-zinc-300">{label}</span>
        <span className="font-mono font-semibold text-red-400">{value}</span>
      </div>
      <input
        type="range"
        min={0}
        max={100}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(Number(e.target.value))}
        className="mt-1.5 w-full accent-red-600 disabled:opacity-60"
      />
    </div>
  );
}

function PolicyCard({
  policy,
  isActive,
  isAdmin,
  onSave,
  onActivate,
}: {
  policy: EnforcementPolicy;
  isActive: boolean;
  isAdmin: boolean;
  onSave: (id: string, updates: PolicyUpdatePayload) => Promise<void>;
  onActivate: (id: string) => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [busy, setBusy] = useState(false);

  const editing = isAdmin && draft !== null;
  const current = draft ?? toDraft(policy);

  const set = (key: string, value: string | number | boolean) =>
    setDraft((d) => ({ ...(d ?? toDraft(policy)), [key]: value }));

  const thresholdError = MODULES.some(
    (m) => Number(current[m.high as string]) <= Number(current[m.medium as string]),
  );

  const handleSave = async () => {
    if (!draft) return;
    if (thresholdError) return;
    setBusy(true);
    try {
      const original = toDraft(policy);
      const updates: PolicyUpdatePayload = {};
      for (const key of Object.keys(draft)) {
        if (draft[key] !== original[key]) {
          (updates as Record<string, unknown>)[key] = draft[key];
        }
      }
      await onSave(policy.id, updates);
      setDraft(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={`rounded-xl border bg-zinc-800/60 ${isActive ? 'border-red-500/40' : 'border-zinc-700/50'}`}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full flex-wrap items-center justify-between gap-2 px-4 py-3 text-left"
      >
        <div className="flex items-center gap-2.5">
          <ChevronDown className={`h-4 w-4 text-zinc-500 transition-transform ${open ? 'rotate-0' : '-rotate-90'}`} />
          <span className="text-sm font-semibold text-zinc-100">{policy.name}</span>
          {isActive && (
            <span className="flex items-center gap-1 rounded-full bg-red-500/15 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-red-400 ring-1 ring-red-500/40">
              <ShieldCheck className="h-3 w-3" /> Active
            </span>
          )}
        </div>
        <span className="max-w-md truncate text-xs text-zinc-500">{policy.description}</span>
      </button>

      {open && (
        <div className="space-y-4 border-t border-zinc-700/50 px-4 py-4">
          {/* Identity */}
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <label className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">Policy name</label>
              <input
                value={String(current.name ?? '')}
                disabled={!editing}
                onChange={(e) => set('name', e.target.value)}
                className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-sm text-zinc-200 outline-none focus:border-red-500/60 disabled:opacity-70"
              />
            </div>
            <div>
              <label className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">Description</label>
              <input
                value={String(current.description ?? '')}
                disabled={!editing}
                onChange={(e) => set('description', e.target.value)}
                className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-sm text-zinc-200 outline-none focus:border-red-500/60 disabled:opacity-70"
              />
            </div>
          </div>

          {/* Thresholds */}
          <div>
            <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-zinc-500">Risk thresholds per threat type</p>
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {MODULES.map((m) => (
                <div key={m.key} className="space-y-2">
                  <p className="text-xs font-semibold text-zinc-300">{m.label}</p>
                  <ThresholdSlider label="High threshold" value={Number(current[m.high as string] ?? 0)} onChange={(v) => set(m.high as string, v)} disabled={!editing} />
                  <ThresholdSlider label="Medium threshold" value={Number(current[m.medium as string] ?? 0)} onChange={(v) => set(m.medium as string, v)} disabled={!editing} />
                  {editing && Number(current[m.high as string]) <= Number(current[m.medium as string]) && (
                    <p className="text-[11px] text-red-400">High must exceed medium.</p>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Actions + auto-execute */}
          <div className="grid gap-4 lg:grid-cols-2">
            <div>
              <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-zinc-500">Action per severity band</p>
              <div className="space-y-2">
                {(['action_on_critical', 'action_on_high', 'action_on_medium', 'action_on_low'] as const).map((key) => (
                  <div key={key} className="flex items-center gap-2">
                    <span className="w-16 shrink-0 font-mono text-[11px] uppercase text-zinc-500">{key.replace('action_on_', '')}</span>
                    <select
                      value={String(current[key] ?? 'allow')}
                      disabled={!editing}
                      onChange={(e) => set(key, e.target.value)}
                      className="flex-1 rounded-lg border border-zinc-700 bg-zinc-900 px-2.5 py-1.5 text-xs text-zinc-200 outline-none focus:border-red-500/60 disabled:opacity-70"
                    >
                      {ACTION_OPTIONS.map((a) => (
                        <option key={a} value={a}>{a}</option>
                      ))}
                    </select>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-zinc-500">Auto-execute &amp; notifications</p>
              <div className="grid gap-2 sm:grid-cols-2">
                <Toggle label="Auto-exec critical" checked={Boolean(current.auto_execute_critical)} onChange={(v) => set('auto_execute_critical', v)} disabled={!editing} />
                <Toggle label="Auto-exec high" checked={Boolean(current.auto_execute_high)} onChange={(v) => set('auto_execute_high', v)} disabled={!editing} />
                <Toggle label="Auto-exec medium" checked={Boolean(current.auto_execute_medium)} onChange={(v) => set('auto_execute_medium', v)} disabled={!editing} />
                <Toggle label="Auto-exec low" checked={Boolean(current.auto_execute_low)} onChange={(v) => set('auto_execute_low', v)} disabled={!editing} />
                <Toggle label="Notify SOC (critical)" checked={Boolean(current.notify_soc_on_critical)} onChange={(v) => set('notify_soc_on_critical', v)} disabled={!editing} />
                <Toggle label="Notify SOC (high)" checked={Boolean(current.notify_soc_on_high)} onChange={(v) => set('notify_soc_on_high', v)} disabled={!editing} />
                <Toggle label="Notify user (medium)" checked={Boolean(current.notify_user_on_medium)} onChange={(v) => set('notify_user_on_medium', v)} disabled={!editing} />
              </div>
            </div>
          </div>

          {/* Controls */}
          <div className="flex flex-wrap items-center gap-2 border-t border-zinc-700/50 pt-3">
            {isAdmin ? (
              <>
                <button
                  disabled={!editing || busy || thresholdError}
                  onClick={handleSave}
                  className="flex items-center gap-1.5 rounded-lg bg-red-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-red-500 disabled:opacity-50 transition"
                >
                  <Save className="h-3.5 w-3.5" /> Save Changes
                </button>
                {editing && (
                  <button
                    onClick={() => setDraft(null)}
                    className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-zinc-400 hover:bg-zinc-800 transition"
                  >
                    Discard
                  </button>
                )}
                {!editing && (
                  <button
                    onClick={() => setDraft(toDraft(policy))}
                    className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs font-semibold text-zinc-200 hover:border-red-500/60 hover:text-red-400 transition"
                  >
                    Edit Policy
                  </button>
                )}
                {!isActive && (
                  <button
                    disabled={busy}
                    onClick={() => onActivate(policy.id)}
                    className="flex items-center gap-1.5 rounded-lg border border-emerald-600/60 px-3 py-1.5 text-xs font-semibold text-emerald-400 hover:bg-emerald-600/10 disabled:opacity-50 transition"
                  >
                    <Zap className="h-3.5 w-3.5" /> Activate
                  </button>
                )}
                {thresholdError && editing && (
                  <span className="text-xs text-red-400">Fix threshold ordering before saving.</span>
                )}
              </>
            ) : (
              <p className="text-xs text-zinc-500">Read-only — policy changes require the organization admin role.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function PolicyManagement() {
  const addToast = useUiStore((s) => s.addToast);
  const can = useAuthStore((s) => s.can);
  const isAdmin = can('admin');

  const { data, loading, error, refetch } = useApi(() => api.listPolicies(), []);

  const handleSave = async (id: string, updates: PolicyUpdatePayload) => {
    if (Object.keys(updates).length === 0) {
      addToast('No changes to save', 'medium');
      return;
    }
    try {
      await api.updatePolicy(id, updates);
      addToast('Policy updated', 'low');
      refetch();
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Policy update failed', 'high');
    }
  };

  const handleActivate = async (id: string) => {
    try {
      await api.activatePolicy(id);
      addToast('Policy activated — enforcement now follows it', 'low');
      refetch();
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Activation failed', 'high');
    }
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="Policy Management"
        description={
          isAdmin
            ? 'Configure enforcement thresholds, actions and auto-execution per severity band. Only one policy is active at a time.'
            : 'Enforcement policy configuration (read-only). Only organization admins can modify policies.'
        }
      />

      {loading ? (
        <div className="space-y-3">
          {Array.from({ length: 2 }).map((_, i) => (
            <PanelSkeleton key={i} height="h-16" />
          ))}
        </div>
      ) : error ? (
        <EmptyState icon={Settings2} title="Failed to load policies" description={error} />
      ) : !data || data.policies.length === 0 ? (
        <EmptyState
          icon={Settings2}
          title="No enforcement policies configured"
          description="Policies are seeded automatically when an organization is created."
        />
      ) : (
        <div className="space-y-3">
          {data.policies.map((p) => (
            <PolicyCard
              key={p.id}
              policy={p}
              isActive={p.id === data.active_policy_id}
              isAdmin={isAdmin}
              onSave={handleSave}
              onActivate={handleActivate}
            />
          ))}
        </div>
      )}
    </div>
  );
}
