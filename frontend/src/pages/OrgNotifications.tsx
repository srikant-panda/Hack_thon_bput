import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  BellRing,
  ChevronDown,
  ChevronUp,
  Loader2,
  Mail,
  MailPlus,
  RefreshCw,
  ScrollText,
  Trash2,
} from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import { useUiStore } from '../store/uiStore';
import * as orgApi from '../services/orgApi';

const ROLE_STYLES: Record<string, string> = {
  admin: 'bg-red-500/15 text-red-400 ring-red-500/40',
  analyst: 'bg-amber-500/15 text-amber-400 ring-amber-500/40',
  viewer: 'bg-zinc-700/40 text-zinc-300 ring-zinc-600/50',
};

const STATUS_STYLES: Record<string, string> = {
  sent: 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/30',
  failed: 'bg-red-500/15 text-red-400 ring-red-500/40',
  skipped: 'bg-zinc-700/30 text-zinc-400 ring-zinc-600/40',
};

const EVENT_LABELS: Record<string, string> = {
  server_down: 'Server Down',
  mail_server_down: 'Mail Server Down',
  critical_log: 'Critical Log',
  impersonation: 'Impersonation',
};

const ROLES: orgApi.RoleGroup[] = ['viewer', 'analyst', 'admin'];

function Toggle({ on, onClick }: { on: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`relative h-5 w-9 rounded-full transition ${on ? 'bg-emerald-600' : 'bg-zinc-700'}`}
    >
      <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition ${on ? 'left-[18px]' : 'left-0.5'}`} />
    </button>
  );
}

/**
 * ORG-4: organization email notification groups — registered addresses
 * grouped by role, per-event-type routing (min role), and delivery history.
 */
export default function OrgNotifications() {
  const { orgId } = useParams<{ orgId: string }>();
  const addToast = useUiStore((s) => s.addToast);
  const [emails, setEmails] = useState<orgApi.NotificationEmail[]>([]);
  const [settings, setSettings] = useState<orgApi.NotificationSetting[]>([]);
  const [logs, setLogs] = useState<orgApi.NotificationLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  // Add-email modal
  const [modalOpen, setModalOpen] = useState(false);
  const [newEmail, setNewEmail] = useState('');
  const [newRole, setNewRole] = useState<orgApi.RoleGroup>('analyst');
  const [adding, setAdding] = useState(false);

  const load = useCallback(async () => {
    if (!orgId) return;
    try {
      const [e, s, l] = await Promise.all([
        orgApi.listNotificationEmails(orgId),
        orgApi.listNotificationSettings(orgId),
        orgApi.listNotificationLogs(orgId, { limit: 10 }),
      ]);
      setEmails(e);
      setSettings(s);
      setLogs(l);
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to load notification settings', 'high');
    } finally {
      setLoading(false);
    }
  }, [orgId, addToast]);

  useEffect(() => {
    load();
  }, [load]);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId || !newEmail.trim()) return;
    setAdding(true);
    try {
      await orgApi.addNotificationEmail(orgId, newEmail.trim(), newRole);
      addToast('Email registered', 'safe');
      setModalOpen(false);
      setNewEmail('');
      await load();
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to add email', 'high');
    } finally {
      setAdding(false);
    }
  };

  const handleToggleEmail = async (row: orgApi.NotificationEmail) => {
    if (!orgId) return;
    try {
      await orgApi.updateNotificationEmail(orgId, row.id, { is_enabled: !row.is_enabled });
      setEmails((prev) => prev.map((x) => (x.id === row.id ? { ...x, is_enabled: !row.is_enabled } : x)));
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Update failed', 'high');
    }
  };

  const handleRoleChange = async (row: orgApi.NotificationEmail, role: orgApi.RoleGroup) => {
    if (!orgId) return;
    try {
      await orgApi.updateNotificationEmail(orgId, row.id, { role });
      setEmails((prev) => prev.map((x) => (x.id === row.id ? { ...x, role } : x)));
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Update failed', 'high');
    }
  };

  const handleDeleteEmail = async (row: orgApi.NotificationEmail) => {
    if (!orgId) return;
    if (!confirm(`Remove ${row.email} from the notification list?`)) return;
    try {
      await orgApi.deleteNotificationEmail(orgId, row.id);
      setEmails((prev) => prev.filter((x) => x.id !== row.id));
      addToast('Email removed', 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Delete failed', 'high');
    }
  };

  const handleMinRole = async (row: orgApi.NotificationSetting, min_role: orgApi.RoleGroup) => {
    if (!orgId) return;
    try {
      await orgApi.updateNotificationSetting(orgId, row.event_type, { min_role });
      setSettings((prev) => prev.map((x) => (x.event_type === row.event_type ? { ...x, min_role } : x)));
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Update failed', 'high');
    }
  };

  const handleToggleEvent = async (row: orgApi.NotificationSetting) => {
    if (!orgId) return;
    try {
      await orgApi.updateNotificationSetting(orgId, row.event_type, { is_enabled: !row.is_enabled });
      setSettings((prev) => prev.map((x) => (x.event_type === row.event_type ? { ...x, is_enabled: !row.is_enabled } : x)));
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Update failed', 'high');
    }
  };

  if (!orgId) return <div className="p-6 text-sm text-zinc-400">No organization selected.</div>;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <PageHeader
          title="Email Notification Groups"
          description="Send email to registered addresses, grouped by role — each event type picks the minimum role group that gets notified."
        />
        <div className="flex items-center gap-2">
          <Link
            to={`/org/${orgId}/notifications/logs`}
            className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 px-3.5 py-2 text-xs font-semibold text-zinc-200 transition hover:border-zinc-500"
          >
            <ScrollText className="h-4 w-4" /> Full Log History
          </Link>
          <button
            onClick={() => setModalOpen(true)}
            className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-3.5 py-2 text-xs font-semibold text-white shadow-lg shadow-red-600/20 transition hover:bg-red-500"
          >
            <MailPlus className="h-4 w-4" /> Add Email
          </button>
        </div>
      </div>

      {loading && <div className="flex items-center gap-2 py-8 text-xs text-zinc-500"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>}

      {!loading && (
        <>
          {/* 1. Registered emails */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur">
            <div className="mb-4 flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
              <Mail className="h-4 w-4 text-red-400" /> Registered Emails (grouped by role)
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-zinc-800 font-mono uppercase tracking-wider text-zinc-500">
                  <tr><th className="py-2 pr-4">Email</th><th className="py-2 pr-4">Role Group</th><th className="py-2 pr-4">Enabled</th><th className="py-2"></th></tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/70">
                  {emails.length === 0 && (
                    <tr><td colSpan={4} className="py-4 text-zinc-500">No addresses registered yet.</td></tr>
                  )}
                  {emails.map((row) => (
                    <tr key={row.id} className="text-zinc-300">
                      <td className="py-2.5 pr-4 font-medium text-zinc-100">{row.email}</td>
                      <td className="py-2.5 pr-4">
                        <select
                          value={row.role}
                          onChange={(e) => handleRoleChange(row, e.target.value as orgApi.RoleGroup)}
                          className="rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-[11px] text-zinc-200 outline-none focus:border-red-500/60"
                        >
                          {ROLES.map((role) => <option key={role} value={role}>{role}</option>)}
                        </select>
                        <span className={`ml-2 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ring-1 ${ROLE_STYLES[row.role]}`}>{row.role}</span>
                      </td>
                      <td className="py-2.5 pr-4"><Toggle on={row.is_enabled} onClick={() => handleToggleEmail(row)} /></td>
                      <td className="py-2.5 text-right">
                        <button
                          onClick={() => handleDeleteEmail(row)}
                          className="inline-flex items-center gap-1 rounded border border-red-500/40 px-2 py-1 text-[11px] text-red-400 transition hover:bg-red-500/10"
                        >
                          <Trash2 className="h-3 w-3" /> Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* 2. Event type settings */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur">
            <div className="mb-4 flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
              <BellRing className="h-4 w-4 text-red-400" /> Event Type Routing
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-zinc-800 font-mono uppercase tracking-wider text-zinc-500">
                  <tr><th className="py-2 pr-4">Event Type</th><th className="py-2 pr-4">Min Role (who gets it)</th><th className="py-2 pr-4">Enabled</th></tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/70">
                  {settings.map((row) => (
                    <tr key={row.event_type} className="text-zinc-300">
                      <td className="py-2.5 pr-4 font-medium text-zinc-100">{EVENT_LABELS[row.event_type] ?? row.event_type}</td>
                      <td className="py-2.5 pr-4">
                        <select
                          value={row.min_role}
                          onChange={(e) => handleMinRole(row, e.target.value as orgApi.RoleGroup)}
                          className="rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-[11px] text-zinc-200 outline-none focus:border-red-500/60"
                        >
                          {ROLES.map((role) => <option key={role} value={role}>{role}</option>)}
                        </select>
                        <span className="ml-2 text-[10px] text-zinc-500">
                          {row.min_role === 'admin' ? 'admins only' : row.min_role === 'analyst' ? 'analysts + admins' : 'everyone'}
                        </span>
                      </td>
                      <td className="py-2.5"><Toggle on={row.is_enabled} onClick={() => handleToggleEvent(row)} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* 3. Recent delivery history */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur">
            <div className="mb-4 flex items-center justify-between">
              <div className="flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
                <ScrollText className="h-4 w-4 text-red-400" /> Recent Deliveries
              </div>
              <button onClick={load} className="inline-flex items-center gap-1.5 text-[11px] text-zinc-400 hover:text-zinc-200">
                <RefreshCw className="h-3 w-3" /> Refresh
              </button>
            </div>
            <div className="space-y-2">
              {logs.length === 0 && <p className="py-2 text-xs text-zinc-500">No notifications sent yet.</p>}
              {logs.map((log) => (
                <div key={log.id} className="rounded-lg border border-zinc-800 bg-zinc-950/60 px-3 py-2.5">
                  <button onClick={() => setExpanded(expanded === log.id ? null : log.id)} className="flex w-full items-center gap-3 text-left">
                    <span className="w-32 shrink-0 font-mono text-[10px] text-zinc-500">
                      {log.created_at ? new Date(log.created_at).toLocaleString() : '—'}
                    </span>
                    <span className="w-32 shrink-0 font-mono text-[10px] uppercase text-zinc-400">{EVENT_LABELS[log.event_type] ?? log.event_type}</span>
                    <span className="min-w-0 flex-1 truncate text-xs text-zinc-300">{log.subject}</span>
                    <span className="shrink-0 text-[10px] text-zinc-500">{log.recipients.length} rcpt</span>
                    <span className={`shrink-0 rounded px-2 py-0.5 text-[10px] uppercase ring-1 ${STATUS_STYLES[log.status]}`}>{log.status}</span>
                    {expanded === log.id ? <ChevronUp className="h-3.5 w-3.5 shrink-0 text-zinc-500" /> : <ChevronDown className="h-3.5 w-3.5 shrink-0 text-zinc-500" />}
                  </button>
                  {expanded === log.id && (
                    <div className="mt-2 space-y-1.5 border-t border-zinc-800 pt-2">
                      {log.recipients.map((rec, i) => (
                        <div key={i} className="flex items-center gap-2 text-[11px]">
                          <span className={`rounded px-1.5 py-0.5 uppercase ring-1 ${STATUS_STYLES[rec.status] ?? ''}`}>{rec.status}</span>
                          <span className={`rounded-full px-1.5 py-0.5 text-[9px] uppercase ring-1 ${ROLE_STYLES[rec.role] ?? ''}`}>{rec.role}</span>
                          <span className="font-mono text-zinc-300">{rec.email}</span>
                          {rec.error_detail && <span className="text-red-400">{rec.error_detail}</span>}
                        </div>
                      ))}
                      {log.error_detail && <p className="text-[11px] text-red-400">{log.error_detail}</p>}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {/* Add-email modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="w-full max-w-md rounded-xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl">
            <h3 className="mb-1 text-sm font-bold text-zinc-100">Register Notification Email</h3>
            <p className="mb-4 text-xs text-zinc-400">The address joins the selected role group; event min_role decides which groups receive which events.</p>
            <form onSubmit={handleAdd}>
              <input
                type="email"
                required
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                placeholder="soc-lead@corp.example"
                className="mb-3 w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 placeholder-zinc-500 outline-none focus:border-red-500/60"
              />
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value as orgApi.RoleGroup)}
                className="mb-5 w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-500/60"
              >
                {ROLES.map((role) => <option key={role} value={role}>{role} group</option>)}
              </select>
              <div className="flex justify-end gap-2">
                <button type="button" onClick={() => setModalOpen(false)} className="rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-300 transition hover:border-zinc-500">Cancel</button>
                <button type="submit" disabled={adding} className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-3 py-2 text-xs font-semibold text-white transition hover:bg-red-500 disabled:opacity-50">
                  {adding && <Loader2 className="h-3.5 w-3.5 animate-spin" />} <span>Add Email</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
