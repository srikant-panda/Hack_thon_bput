import { useCallback, useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import {
  AlertTriangle,
  Check,
  Copy,
  KeyRound,
  Loader2,
  Plus,
  Trash2,
  UserPlus,
  Users,
} from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import { useUiStore } from '../store/uiStore';
import * as orgApi from '../services/orgApi';

const ROLE_STYLES: Record<orgApi.OrgMember['role'], string> = {
  admin: 'bg-red-500/15 text-red-400 ring-red-500/40',
  analyst: 'bg-amber-500/15 text-amber-400 ring-amber-500/40',
  viewer: 'bg-zinc-700/40 text-zinc-300 ring-zinc-600/50',
};

const ROLES: orgApi.OrgMember['role'][] = ['viewer', 'analyst', 'admin'];

function formatDate(value: string | null | undefined): string {
  if (!value) return '—';
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

/**
 * ORG-1: organization settings (admin-only): API key lifecycle + members.
 * The plaintext API key is shown exactly once after creation.
 */
export default function OrganizationSettings() {
  const { orgId } = useParams<{ orgId: string }>();
  const addToast = useUiStore((s) => s.addToast);

  const [keys, setKeys] = useState<orgApi.OrgApiKey[]>([]);
  const [members, setMembers] = useState<orgApi.OrgMember[]>([]);
  const [loading, setLoading] = useState(true);

  // Create-key modal state
  const [keyModalOpen, setKeyModalOpen] = useState(false);
  const [keyName, setKeyName] = useState('');
  const [keyExpiry, setKeyExpiry] = useState('');
  const [creatingKey, setCreatingKey] = useState(false);
  const [createdKey, setCreatedKey] = useState<orgApi.OrgApiKeyCreated | null>(null);
  const [copied, setCopied] = useState(false);

  // Invite member form
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<orgApi.OrgMember['role']>('analyst');
  const [inviting, setInviting] = useState(false);
  const [savingUserId, setSavingUserId] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const [keyList, memberList] = await Promise.all([
        orgApi.listApiKeys(orgId),
        orgApi.listMembers(orgId),
      ]);
      setKeys(keyList);
      setMembers(memberList);
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to load organization settings', 'high');
    } finally {
      setLoading(false);
    }
  }, [orgId, addToast]);

  useEffect(() => {
    load();
  }, [load]);

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId || !keyName.trim()) return;
    setCreatingKey(true);
    try {
      const created = await orgApi.createApiKey(
        orgId,
        keyName.trim(),
        keyExpiry ? new Date(keyExpiry).toISOString() : null,
      );
      setCreatedKey(created);
      setKeyName('');
      setKeyExpiry('');
      const list = await orgApi.listApiKeys(orgId);
      setKeys(list);
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to create API key', 'high');
    } finally {
      setCreatingKey(false);
    }
  };

  const handleCopyKey = async () => {
    if (!createdKey) return;
    try {
      await navigator.clipboard.writeText(createdKey.key);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      addToast('Copy failed — select the key text manually', 'medium');
    }
  };

  const handleRevoke = async (key: orgApi.OrgApiKey) => {
    if (!orgId) return;
    if (!confirm(`Revoke API key "${key.name}" (${key.keyPrefix}…)? Integrations using it will stop working.`)) return;
    try {
      await orgApi.revokeApiKey(orgId, key.id);
      setKeys((prev) => prev.map((k) => (k.id === key.id ? { ...k, status: 'revoked' } : k)));
      addToast('API key revoked', 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to revoke key', 'high');
    }
  };

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId || !inviteEmail.trim()) return;
    setInviting(true);
    try {
      const member = await orgApi.addMember(orgId, inviteEmail.trim(), inviteRole);
      setMembers((prev) => [...prev, member]);
      setInviteEmail('');
      addToast(`Added ${member.email ?? 'member'} as ${member.role}`, 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to add member', 'high');
    } finally {
      setInviting(false);
    }
  };

  const handleChangeRole = async (member: orgApi.OrgMember, role: orgApi.OrgMember['role']) => {
    if (!orgId) return;
    setSavingUserId(member.userId);
    try {
      await orgApi.updateMemberRole(orgId, member.userId, role);
      setMembers((prev) => prev.map((m) => (m.userId === member.userId ? { ...m, role } : m)));
      addToast('Member role updated', 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to update role', 'high');
    } finally {
      setSavingUserId(null);
    }
  };

  const handleRemove = async (member: orgApi.OrgMember) => {
    if (!orgId) return;
    if (!confirm(`Remove ${member.email ?? member.userId} from the organization?`)) return;
    setSavingUserId(member.userId);
    try {
      await orgApi.removeMember(orgId, member.userId);
      setMembers((prev) => prev.filter((m) => m.userId !== member.userId));
      addToast('Member removed', 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to remove member', 'high');
    } finally {
      setSavingUserId(null);
    }
  };

  if (!orgId) {
    return <div className="p-6 text-sm text-zinc-400">No organization selected.</div>;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Organization Settings"
        description="API keys for the org gateway, and team members with role-based access (admin, analyst, viewer)."
      />

      {/* ------------------------------------------------ API Keys (admin) */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
            <KeyRound className="h-4 w-4 text-red-400" />
            <span>API Keys (gateway access)</span>
          </div>
          <button
            onClick={() => {
              setCreatedKey(null);
              setKeyModalOpen(true);
            }}
            className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-3 py-1.5 text-xs font-semibold text-white shadow-lg shadow-red-600/20 transition hover:bg-red-500"
          >
            <Plus className="h-3.5 w-3.5" />
            <span>Create New Key</span>
          </button>
        </div>

        {/* Plaintext shown exactly once */}
        {createdKey && (
          <div className="mb-4 rounded-lg border border-amber-500/40 bg-amber-500/5 p-4">
            <div className="mb-2 flex items-center gap-2 text-xs font-bold text-amber-300">
              <AlertTriangle className="h-4 w-4" />
              Copy this key now — it will never be shown again
            </div>
            <div className="flex items-center gap-2">
              <code className="flex-1 overflow-x-auto rounded bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-100">
                {createdKey.key}
              </code>
              <button
                onClick={handleCopyKey}
                className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-900 px-2.5 py-2 text-xs text-zinc-200 transition hover:border-zinc-500"
              >
                {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <p className="mt-2 text-[11px] text-amber-300/70">
              Store it in your secret manager. Only a SHA-256 hash is kept server-side; use it in
              the <code className="font-mono">org_authorization</code> header on gateway calls.
            </p>
          </div>
        )}

        {loading ? (
          <div className="flex items-center gap-2 py-6 text-xs text-zinc-500">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading…
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-zinc-800 font-mono uppercase tracking-wider text-zinc-500">
                <tr>
                  <th className="py-2 pr-4">Name</th>
                  <th className="py-2 pr-4">Prefix</th>
                  <th className="py-2 pr-4">Last Used</th>
                  <th className="py-2 pr-4">Expires</th>
                  <th className="py-2 pr-4">Status</th>
                  <th className="py-2"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/70">
                {keys.length === 0 && (
                  <tr>
                    <td colSpan={6} className="py-4 text-zinc-500">
                      No API keys yet — create one to connect mail servers or SIEM pipelines.
                    </td>
                  </tr>
                )}
                {keys.map((k) => (
                  <tr key={k.id} className="text-zinc-300">
                    <td className="py-2.5 pr-4 font-medium text-zinc-100">{k.name}</td>
                    <td className="py-2.5 pr-4 font-mono text-zinc-400">{k.keyPrefix}…</td>
                    <td className="py-2.5 pr-4 text-zinc-400">{formatDate(k.lastUsedAt)}</td>
                    <td className="py-2.5 pr-4 text-zinc-400">{k.expiresAt ? formatDate(k.expiresAt) : 'Never'}</td>
                    <td className="py-2.5 pr-4">
                      <span
                        className={`rounded-full px-2 py-0.5 font-mono text-[10px] uppercase ring-1 ${
                          k.status === 'active'
                            ? 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/30'
                            : 'bg-zinc-700/30 text-zinc-400 ring-zinc-600/40'
                        }`}
                      >
                        {k.status}
                      </span>
                    </td>
                    <td className="py-2.5 text-right">
                      {k.status === 'active' && (
                        <button
                          onClick={() => handleRevoke(k)}
                          className="inline-flex items-center gap-1 rounded border border-red-500/40 px-2 py-1 text-[11px] text-red-400 transition hover:bg-red-500/10"
                        >
                          <Trash2 className="h-3 w-3" /> Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ------------------------------------------------ Members */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur">
        <div className="mb-4 flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
          <Users className="h-4 w-4 text-red-400" />
          <span>Members & Roles</span>
        </div>

        <form onSubmit={handleInvite} className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center">
          <input
            type="email"
            required
            value={inviteEmail}
            onChange={(e) => setInviteEmail(e.target.value)}
            placeholder="analyst@organization.com"
            className="flex-1 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 placeholder-zinc-500 outline-none focus:border-red-500/60"
          />
          <select
            value={inviteRole}
            onChange={(e) => setInviteRole(e.target.value as orgApi.OrgMember['role'])}
            className="rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-500/60"
          >
            {ROLES.map((role) => (
              <option key={role} value={role}>
                {role}
              </option>
            ))}
          </select>
          <button
            type="submit"
            disabled={inviting}
            className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-3 py-2 text-xs font-semibold text-white transition hover:bg-red-500 disabled:opacity-50"
          >
            {inviting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <UserPlus className="h-3.5 w-3.5" />}
            <span>Invite Member</span>
          </button>
        </form>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-zinc-800 font-mono uppercase tracking-wider text-zinc-500">
              <tr>
                <th className="py-2 pr-4">Member</th>
                <th className="py-2 pr-4">Email</th>
                <th className="py-2 pr-4">Role</th>
                <th className="py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/70">
              {members.map((m) => (
                <tr key={m.id} className="text-zinc-300">
                  <td className="py-2.5 pr-4 font-medium text-zinc-100">{m.fullName ?? '—'}</td>
                  <td className="py-2.5 pr-4 text-zinc-400">{m.email ?? '—'}</td>
                  <td className="py-2.5 pr-4">
                    <div className="flex items-center gap-2">
                      <select
                        value={m.role}
                        onChange={(e) => handleChangeRole(m, e.target.value as orgApi.OrgMember['role'])}
                        className="rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-[11px] text-zinc-200 outline-none focus:border-red-500/60"
                      >
                        {ROLES.map((role) => (
                          <option key={role} value={role}>
                            {role}
                          </option>
                        ))}
                      </select>
                      <span className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ring-1 ${ROLE_STYLES[m.role]}`}>
                        {m.role}
                      </span>
                    </div>
                  </td>
                  <td className="py-2.5 text-right">
                    <button
                      onClick={() => handleRemove(m)}
                      disabled={savingUserId === m.userId}
                      className="inline-flex items-center gap-1 rounded border border-red-500/40 px-2 py-1 text-[11px] text-red-400 transition hover:bg-red-500/10 disabled:opacity-50"
                    >
                      <Trash2 className="h-3 w-3" /> Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-[11px] text-zinc-500">
          Admins manage keys, members and settings. Analysts run analyses. Viewers are read-only
          and cannot access sensitive settings (API keys, billing).
        </p>
      </div>

      {/* ------------------------------------------------ Create-key modal */}
      {keyModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="w-full max-w-md rounded-xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl">
            <h3 className="mb-1 text-sm font-bold text-zinc-100">Create API Key</h3>
            <p className="mb-4 text-xs text-zinc-400">
              Keys authenticate server-to-server calls to the org gateway via the{' '}
              <code className="font-mono text-zinc-300">org_authorization</code> header.
            </p>
            <form onSubmit={handleCreateKey}>
              <label className="mb-1.5 block text-xs font-semibold text-zinc-300">Key name</label>
              <input
                type="text"
                required
                maxLength={120}
                value={keyName}
                onChange={(e) => setKeyName(e.target.value)}
                placeholder="Production Key"
                className="mb-3 w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 placeholder-zinc-500 outline-none focus:border-red-500/60"
              />
              <label className="mb-1.5 block text-xs font-semibold text-zinc-300">
                Expiry (optional — blank = never)
              </label>
              <input
                type="date"
                value={keyExpiry}
                onChange={(e) => setKeyExpiry(e.target.value)}
                className="mb-5 w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 outline-none focus:border-red-500/60"
              />
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setKeyModalOpen(false)}
                  className="rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-300 transition hover:border-zinc-500"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingKey || !keyName.trim()}
                  className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-3 py-2 text-xs font-semibold text-white transition hover:bg-red-500 disabled:opacity-50"
                >
                  {creatingKey && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                  <span>Create Key</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
