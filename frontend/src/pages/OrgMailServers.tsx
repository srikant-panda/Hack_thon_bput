import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  FileClock,
  KeyRound,
  Link2,
  Loader2,
  Mail,
  MailPlus,
  PlugZap,
  ScrollText,
  Settings2,
  Trash2,
  Unlink,
} from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import { useUiStore } from '../store/uiStore';
import * as orgApi from '../services/orgApi';

const STATUS_STYLES: Record<string, string> = {
  connected: 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/30',
  disconnected: 'bg-zinc-700/30 text-zinc-400 ring-zinc-600/40',
  error: 'bg-red-500/15 text-red-400 ring-red-500/40',
};

const PROVIDER_LABELS: Record<orgApi.MailProviderType, string> = {
  google_workspace: 'Google Workspace',
  microsoft_365: 'Microsoft 365',
  imap_smtp: 'IMAP / SMTP',
};

/**
 * ORG-3: server-management style table for org mail servers — infrastructure
 * assets with per-server settings and log streams, NOT a personal mailbox.
 */
export default function OrgMailServers() {
  const { orgId } = useParams<{ orgId: string }>();
  const addToast = useUiStore((s) => s.addToast);
  const [servers, setServers] = useState<orgApi.MailServer[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);

  // Add-server form state
  const [name, setName] = useState('');
  const [provider, setProvider] = useState<orgApi.MailProviderType>('google_workspace');
  const [creds, setCreds] = useState<orgApi.MailServerCredentialDraft>({});
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    if (!orgId) return;
    try {
      setServers(await orgApi.listMailServers(orgId));
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to load mail servers', 'high');
    } finally {
      setLoading(false);
    }
  }, [orgId, addToast]);

  useEffect(() => {
    load();
  }, [load]);

  const resetForm = () => {
    setName('');
    setProvider('google_workspace');
    setCreds({});
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId || !name.trim()) return;
    setCreating(true);
    try {
      const created = await orgApi.createMailServer(orgId, name.trim(), provider, creds);
      addToast(`Mail server "${created.name}" created (${created.status})`, 'safe');
      setModalOpen(false);
      resetForm();
      await load();
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to create mail server', 'high');
    } finally {
      setCreating(false);
    }
  };

  const handleConnect = async (server: orgApi.MailServer) => {
    if (!orgId) return;
    setBusyId(server.id);
    try {
      await orgApi.connectMailServer(orgId, server.id);
      addToast(`"${server.name}" connected`, 'safe');
      await load();
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Connect failed', 'high');
      await load();
    } finally {
      setBusyId(null);
    }
  };

  const handleDisconnect = async (server: orgApi.MailServer) => {
    if (!orgId) return;
    setBusyId(server.id);
    try {
      await orgApi.disconnectMailServer(orgId, server.id);
      addToast(`"${server.name}" disconnected gracefully (mail server unaffected)`, 'safe');
      await load();
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Disconnect failed', 'high');
    } finally {
      setBusyId(null);
    }
  };

  const handleDelete = async (server: orgApi.MailServer) => {
    if (!orgId) return;
    if (!confirm(`Delete mail server "${server.name}"? Credentials and its log stream are removed. The mail server itself keeps running.`)) return;
    setBusyId(server.id);
    try {
      await orgApi.deleteMailServer(orgId, server.id);
      addToast(`"${server.name}" deleted`, 'safe');
      await load();
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Delete failed', 'high');
    } finally {
      setBusyId(null);
    }
  };

  if (!orgId) return <div className="p-6 text-sm text-zinc-400">No organization selected.</div>;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <PageHeader
          title="Mail Servers"
          description="Server-to-server connectors for your organization's mail infrastructure (Google Workspace, Microsoft 365, IMAP/SMTP). Each server has its own settings and log stream."
        />
        <button
          onClick={() => {
            resetForm();
            setModalOpen(true);
          }}
          className="inline-flex items-center gap-2 self-start rounded-lg bg-red-600 px-3.5 py-2 text-xs font-semibold text-white shadow-lg shadow-red-600/20 transition hover:bg-red-500"
        >
          <MailPlus className="h-4 w-4" />
          <span>Add Mail Server</span>
        </button>
      </div>

      <div className="overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-900/90 backdrop-blur">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-zinc-800 font-mono uppercase tracking-wider text-zinc-500">
            <tr>
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Provider</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Last Connected</th>
              <th className="px-4 py-3">Credentials</th>
              <th className="px-4 py-3">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/70">
            {loading && (
              <tr><td colSpan={6} className="px-4 py-6 text-zinc-500"><Loader2 className="mr-2 inline h-4 w-4 animate-spin" />Loading…</td></tr>
            )}
            {!loading && servers.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-6 text-zinc-500">No mail servers registered — add one to start scanning your organization's mail infrastructure.</td></tr>
            )}
            {!loading &&
              servers.map((s) => (
                <tr key={s.id} className="text-zinc-300">
                  <td className="px-4 py-3 font-medium text-zinc-100">{s.name}</td>
                  <td className="px-4 py-3">{PROVIDER_LABELS[s.provider_type]}</td>
                  <td className="px-4 py-3" title={s.last_error ?? undefined}>
                    <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 font-mono text-[10px] uppercase ring-1 ${STATUS_STYLES[s.status]}`}>
                      {s.status === 'connected' ? <Link2 className="h-3 w-3" /> : s.status === 'error' ? <FileClock className="h-3 w-3" /> : <Unlink className="h-3 w-3" />}
                      {s.status}
                    </span>
                    {s.last_error && <span className="ml-2 max-w-[180px] truncate align-middle text-[10px] text-red-400" title={s.last_error}>{s.last_error}</span>}
                  </td>
                  <td className="px-4 py-3 font-mono text-zinc-500">
                    {s.last_connected_at ? new Date(s.last_connected_at).toLocaleString() : '—'}
                  </td>
                  <td className="px-4 py-3">
                    {s.has_credentials ? (
                      <span className="inline-flex items-center gap-1 text-[11px] text-zinc-400"><KeyRound className="h-3 w-3 text-emerald-400" /> stored (encrypted)</span>
                    ) : (
                      <span className="text-[11px] text-zinc-600">none</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1.5">
                      {s.status !== 'connected' && (
                        <button
                          onClick={() => handleConnect(s)}
                          disabled={busyId === s.id}
                          className="inline-flex items-center gap-1 rounded border border-emerald-500/40 px-2 py-1 text-[11px] text-emerald-400 transition hover:bg-emerald-500/10 disabled:opacity-50"
                        >
                          {busyId === s.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <PlugZap className="h-3 w-3" />} Connect
                        </button>
                      )}
                      {s.status === 'connected' && (
                        <button
                          onClick={() => handleDisconnect(s)}
                          disabled={busyId === s.id}
                          className="inline-flex items-center gap-1 rounded border border-amber-500/40 px-2 py-1 text-[11px] text-amber-400 transition hover:bg-amber-500/10 disabled:opacity-50"
                        >
                          <Unlink className="h-3 w-3" /> Disconnect
                        </button>
                      )}
                      <Link
                        to={`/org/${orgId}/mail-servers/${s.id}/logs`}
                        className="inline-flex items-center gap-1 rounded border border-zinc-700 px-2 py-1 text-[11px] text-zinc-300 transition hover:border-zinc-500"
                      >
                        <ScrollText className="h-3 w-3" /> Logs
                      </Link>
                      <Link
                        to={`/org/${orgId}/mail-servers/${s.id}/settings`}
                        className="inline-flex items-center gap-1 rounded border border-zinc-700 px-2 py-1 text-[11px] text-zinc-300 transition hover:border-zinc-500"
                      >
                        <Settings2 className="h-3 w-3" /> Settings
                      </Link>
                      <button
                        onClick={() => handleDelete(s)}
                        disabled={busyId === s.id}
                        className="inline-flex items-center gap-1 rounded border border-red-500/40 px-2 py-1 text-[11px] text-red-400 transition hover:bg-red-500/10 disabled:opacity-50"
                      >
                        <Trash2 className="h-3 w-3" /> Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      <p className="flex items-center gap-2 text-[11px] text-zinc-500">
        <Mail className="h-3.5 w-3.5" />
        Disconnecting is graceful: CYBERGUARD stops reading the server, the mail server itself keeps
        running, and credentials are retained for a quick reconnect. Deleting removes the stored
        credentials and this server's log stream.
      </p>

      {/* Add mail server modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl">
            <h3 className="mb-1 text-sm font-bold text-zinc-100">Add Mail Server</h3>
            <p className="mb-4 text-xs text-zinc-400">Server-to-server connector — credentials are encrypted at rest and never displayed again.</p>
            <form onSubmit={handleCreate}>
              <label className="mb-1.5 block text-xs font-semibold text-zinc-300">Server name</label>
              <input
                type="text"
                required
                maxLength={120}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Primary Gmail"
                className="mb-3 w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 placeholder-zinc-500 outline-none focus:border-red-500/60"
              />
              <label className="mb-1.5 block text-xs font-semibold text-zinc-300">Provider</label>
              <select
                value={provider}
                onChange={(e) => {
                  setProvider(e.target.value as orgApi.MailProviderType);
                  setCreds({});
                }}
                className="mb-3 w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-500/60"
              >
                <option value="google_workspace">Google Workspace (domain-wide delegation)</option>
                <option value="microsoft_365">Microsoft 365 (Graph, admin consent)</option>
                <option value="imap_smtp">IMAP / SMTP</option>
              </select>

              {provider === 'google_workspace' && (
                <>
                  <label className="mb-1.5 block text-xs font-semibold text-zinc-300">Service account key (JSON, private key)</label>
                  <textarea
                    rows={3}
                    value={creds.service_account_key ?? ''}
                    onChange={(e) => setCreds((c) => ({ ...c, service_account_key: e.target.value }))}
                    placeholder="-----BEGIN PRIVATE KEY-----"
                    className="mb-3 w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-100 placeholder-zinc-500 outline-none focus:border-red-500/60"
                  />
                  <label className="mb-1.5 block text-xs font-semibold text-zinc-300">Delegated user (scanner mailbox)</label>
                  <input
                    type="email"
                    value={creds.delegated_user ?? ''}
                    onChange={(e) => setCreds((c) => ({ ...c, delegated_user: e.target.value }))}
                    placeholder="scanner@corp.example"
                    className="mb-3 w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 placeholder-zinc-500 outline-none focus:border-red-500/60"
                  />
                </>
              )}
              {provider === 'microsoft_365' && (
                <>
                  <label className="mb-1.5 block text-xs font-semibold text-zinc-300">Client ID</label>
                  <input type="text" value={creds.client_id ?? ''} onChange={(e) => setCreds((c) => ({ ...c, client_id: e.target.value }))}
                    className="mb-3 w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 outline-none focus:border-red-500/60" />
                  <label className="mb-1.5 block text-xs font-semibold text-zinc-300">Client Secret</label>
                  <input type="password" value={creds.client_secret ?? ''} onChange={(e) => setCreds((c) => ({ ...c, client_secret: e.target.value }))}
                    className="mb-3 w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 outline-none focus:border-red-500/60" />
                  <label className="mb-1.5 block text-xs font-semibold text-zinc-300">Tenant ID</label>
                  <input type="text" value={creds.tenant_id ?? ''} onChange={(e) => setCreds((c) => ({ ...c, tenant_id: e.target.value }))}
                    className="mb-3 w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 outline-none focus:border-red-500/60" />
                </>
              )}
              {provider === 'imap_smtp' && (
                <>
                  <div className="mb-3 flex gap-3">
                    <div className="flex-1">
                      <label className="mb-1.5 block text-xs font-semibold text-zinc-300">Host</label>
                      <input type="text" value={creds.host ?? ''} onChange={(e) => setCreds((c) => ({ ...c, host: e.target.value }))}
                        placeholder="mail.corp.example"
                        className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 placeholder-zinc-500 outline-none focus:border-red-500/60" />
                    </div>
                    <div className="w-24">
                      <label className="mb-1.5 block text-xs font-semibold text-zinc-300">Port</label>
                      <input type="number" value={creds.port ?? ''} onChange={(e) => setCreds((c) => ({ ...c, port: Number(e.target.value) }))}
                        placeholder="993"
                        className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 placeholder-zinc-500 outline-none focus:border-red-500/60" />
                    </div>
                  </div>
                  <label className="mb-1.5 block text-xs font-semibold text-zinc-300">Username</label>
                  <input type="text" value={creds.username ?? ''} onChange={(e) => setCreds((c) => ({ ...c, username: e.target.value }))}
                    className="mb-3 w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 outline-none focus:border-red-500/60" />
                  <label className="mb-1.5 block text-xs font-semibold text-zinc-300">Password / app password</label>
                  <input type="password" value={creds.password ?? ''} onChange={(e) => setCreds((c) => ({ ...c, password: e.target.value }))}
                    className="mb-3 w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 outline-none focus:border-red-500/60" />
                </>
              )}

              <div className="mt-5 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setModalOpen(false)}
                  className="rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-300 transition hover:border-zinc-500"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating || !name.trim()}
                  className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-3 py-2 text-xs font-semibold text-white transition hover:bg-red-500 disabled:opacity-50"
                >
                  {creating && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                  <span>Create & Connect</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
