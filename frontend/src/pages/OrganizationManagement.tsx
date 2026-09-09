import { useEffect, useState } from 'react';
import {
  Building2,
  Loader2,
  Plus,
  Shield,
  Trash2,
  UserCheck,
  UserPlus,
  Users,
} from 'lucide-react';
import * as api from '../services/api';
import type { OrganizationMember, OrganizationRole } from '../types';
import { useAuthStore } from '../store/authStore';
import { useUiStore } from '../store/uiStore';
import PageHeader from '../components/common/PageHeader';
import { PanelSkeleton } from '../components/common/LoadingSkeleton';
import { formatTime } from '../constants';

const ROLE_STYLES: Record<OrganizationRole, string> = {
  admin: 'bg-red-500/15 text-red-400 ring-red-500/40',
  analyst: 'bg-amber-500/15 text-amber-400 ring-amber-500/40',
  viewer: 'bg-zinc-700/40 text-zinc-300 ring-zinc-600/50',
};

const ROLES: OrganizationRole[] = ['viewer', 'analyst', 'admin'];

export default function OrganizationManagement() {
  const addToast = useUiStore((s) => s.addToast);
  const activeOrganization = useAuthStore((s) => s.activeOrganization);
  const organizations = useAuthStore((s) => s.organizations);
  const switchOrganization = useAuthStore((s) => s.switchOrganization);
  const fetchUserContext = useAuthStore((s) => s.fetchUserContext);
  const user = useAuthStore((s) => s.user);

  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [loading, setLoading] = useState(false);
  const [savingUserId, setSavingUserId] = useState<string | null>(null);

  // Invite member form state
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<OrganizationRole>('analyst');
  const [inviting, setInviting] = useState(false);

  // Create organization modal state
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [newOrgName, setNewOrgName] = useState('');
  const [creatingOrg, setCreatingOrg] = useState(false);

  const currentOrg = activeOrganization || (organizations.length > 0 ? organizations[0] : null);
  const userRole = currentOrg?.role || user?.role || 'analyst';
  const isAdmin = userRole === 'admin' || currentOrg?.is_personal;

  const loadMembers = async (orgId: string) => {
    setLoading(true);
    try {
      const list = await api.listOrganizationMembers(orgId);
      setMembers(list);
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to load organization members', 'high');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (currentOrg?.id && !currentOrg.is_personal) {
      loadMembers(currentOrg.id);
    } else {
      setMembers([]);
    }
  }, [currentOrg?.id, currentOrg?.is_personal]);

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentOrg?.id) return;
    if (!inviteEmail.trim()) {
      addToast('Please provide a valid email address', 'medium');
      return;
    }

    setInviting(true);
    try {
      const newMember = await api.addOrganizationMember(currentOrg.id, inviteEmail.trim(), inviteRole);
      setMembers((prev) => [...prev, newMember]);
      setInviteEmail('');
      addToast(`Added ${inviteEmail} as ${inviteRole}`, 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to add member', 'high');
    } finally {
      setInviting(false);
    }
  };

  const handleChangeRole = async (targetUserId: string, newRole: OrganizationRole) => {
    if (!currentOrg?.id) return;
    setSavingUserId(targetUserId);
    try {
      await api.updateOrganizationMemberRole(currentOrg.id, targetUserId, newRole);
      setMembers((prev) =>
        prev.map((m) => (m.userId === targetUserId ? { ...m, role: newRole } : m))
      );
      addToast('Member role updated successfully', 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to update member role', 'high');
    } finally {
      setSavingUserId(null);
    }
  };

  const handleRemoveMember = async (targetUserId: string, memberEmail?: string | null) => {
    if (!currentOrg?.id) return;
    if (!confirm(`Are you sure you want to remove ${memberEmail || 'this member'} from the organization?`)) {
      return;
    }

    setSavingUserId(targetUserId);
    try {
      await api.removeOrganizationMember(currentOrg.id, targetUserId);
      setMembers((prev) => prev.filter((m) => m.userId !== targetUserId));
      addToast('Member removed from organization', 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to remove member', 'high');
    } finally {
      setSavingUserId(null);
    }
  };

  const handleCreateOrg = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newOrgName.trim()) return;

    setCreatingOrg(true);
    try {
      const created = await api.createOrganization(newOrgName.trim());
      addToast(`Created organization "${created.name}"`, 'safe');
      setCreateModalOpen(false);
      setNewOrgName('');
      await switchOrganization(created.id);
      await fetchUserContext();
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to create organization', 'high');
    } finally {
      setCreatingOrg(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <PageHeader
          title="Organization & Team Control"
          description="Manage multi-tenant workspaces, team members, and role-based permissions (admin, analyst, viewer)."
        />
        <button
          onClick={() => setCreateModalOpen(true)}
          className="inline-flex items-center gap-2 self-start rounded-lg bg-red-600 px-3.5 py-2 text-xs font-semibold text-white shadow-lg shadow-red-600/20 transition hover:bg-red-500"
        >
          <Plus className="h-4 w-4" />
          <span>New Organization</span>
        </button>
      </div>

      {/* Active Organization Info Card */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3.5">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-red-500/10 ring-1 ring-red-500/30">
              {currentOrg?.is_personal ? (
                <Shield className="h-6 w-6 text-red-400" />
              ) : (
                <Building2 className="h-6 w-6 text-red-400" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-zinc-100">{currentOrg?.name ?? 'Personal Workspace'}</h2>
                <span
                  className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ring-1 ${
                    ROLE_STYLES[userRole]
                  }`}
                >
                  {userRole}
                </span>
                {currentOrg?.is_personal ? (
                  <span className="rounded bg-zinc-800 px-2 py-0.5 font-mono text-[10px] text-zinc-400">
                    Personal Workspace
                  </span>
                ) : (
                  <span className="rounded bg-red-500/10 px-2 py-0.5 font-mono text-[10px] text-red-400">
                    Team Organization
                  </span>
                )}
              </div>
              <p className="mt-1 font-mono text-xs text-zinc-500">
                Workspace ID: {currentOrg?.id} • Slug: {currentOrg?.slug}
              </p>
            </div>
          </div>

          {/* Organization Switcher Dropdown */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-zinc-400">Active Workspace:</span>
            <select
              value={currentOrg?.id ?? ''}
              onChange={(e) => switchOrganization(e.target.value)}
              className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-xs text-zinc-200 outline-none focus:border-red-500/60"
            >
              {organizations.map((org) => (
                <option key={org.id} value={org.id} className="bg-zinc-900">
                  {org.name} ({org.is_personal ? 'Personal' : 'Team'} • {org.role})
                </option>
              ))}
            </select>
          </div>
        </div>

        {currentOrg?.is_personal && (
          <div className="mt-4 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3.5 text-xs leading-relaxed text-amber-300">
            <span className="font-bold">Single-User Personal Workspace:</span> You have unrestricted administrator access to your private security events and playbooks. To invite additional security analysts or SOC team members with RBAC roles, create a <strong>Team Organization</strong>.
          </div>
        )}
      </div>

      {/* Team Management (only for team organizations) */}
      {!currentOrg?.is_personal && (
        <div className="space-y-5">
          {/* Invite Member Form (Admins only) */}
          {isAdmin && (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur">
              <div className="flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300 mb-3">
                <UserPlus className="h-4 w-4 text-red-400" />
                <span>Invite SOC Team Member</span>
              </div>
              <form onSubmit={handleInvite} className="flex flex-col gap-3 sm:flex-row sm:items-center">
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
                  onChange={(e) => setInviteRole(e.target.value as OrganizationRole)}
                  className="rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-500/60"
                >
                  <option value="analyst">Analyst (Triage & Response)</option>
                  <option value="viewer">Viewer (Read-Only)</option>
                  <option value="admin">Admin (Full Control)</option>
                </select>
                <button
                  type="submit"
                  disabled={inviting}
                  className="flex items-center justify-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-red-500 disabled:opacity-50"
                >
                  {inviting ? <Loader2 className="h-4 w-4 animate-spin" /> : <UserCheck className="h-4 w-4" />}
                  <span>Add Member</span>
                </button>
              </form>
            </div>
          )}

          {/* Members Table */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
                <Users className="h-4 w-4 text-red-400" />
                <span>Organization Members ({members.length})</span>
              </div>
            </div>

            {loading ? (
              <PanelSkeleton height="h-48" />
            ) : members.length === 0 ? (
              <div className="py-10 text-center text-xs text-zinc-500">No members found in this organization.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-zinc-800 text-[11px] font-semibold uppercase tracking-wider text-zinc-400">
                    <tr>
                      <th className="pb-3">Member</th>
                      <th className="pb-3">Role</th>
                      <th className="pb-3">Joined</th>
                      {isAdmin && <th className="pb-3 text-right">Actions</th>}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/60">
                    {members.map((m) => {
                      const isSelf = m.userId === user?.id;
                      return (
                        <tr key={m.id} className="transition hover:bg-zinc-800/30">
                          <td className="py-3 pr-3">
                            <div className="font-medium text-zinc-200">{m.fullName || 'Security Analyst'}</div>
                            <div className="font-mono text-[11px] text-zinc-500">{m.email || m.userId}</div>
                          </td>
                          <td className="py-3 pr-3">
                            {isAdmin && !isSelf ? (
                              <select
                                value={m.role}
                                disabled={savingUserId === m.userId}
                                onChange={(e) =>
                                  handleChangeRole(m.userId, e.target.value as OrganizationRole)
                                }
                                className={`rounded-full px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ring-1 outline-none ${
                                  ROLE_STYLES[m.role]
                                } bg-zinc-950`}
                              >
                                {ROLES.map((r) => (
                                  <option key={r} value={r} className="bg-zinc-900 text-zinc-200">
                                    {r}
                                  </option>
                                ))}
                              </select>
                            ) : (
                              <span
                                className={`rounded-full px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ring-1 ${
                                  ROLE_STYLES[m.role]
                                }`}
                              >
                                {m.role}
                              </span>
                            )}
                          </td>
                          <td className="py-3 pr-3 font-mono text-[11px] text-zinc-500">
                            {formatTime(m.joinedAt)}
                          </td>
                          {isAdmin && (
                            <td className="py-3 text-right">
                              {!isSelf && (
                                <button
                                  onClick={() => handleRemoveMember(m.userId, m.email)}
                                  disabled={savingUserId === m.userId}
                                  className="rounded p-1.5 text-zinc-400 hover:bg-red-500/15 hover:text-red-400 transition"
                                  title="Remove Member"
                                >
                                  <Trash2 className="h-3.5 w-3.5" />
                                </button>
                              )}
                            </td>
                          )}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Create Organization Modal */}
      {createModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl">
            <h3 className="text-base font-bold text-zinc-100">Create New Team Organization</h3>
            <p className="mt-1 text-xs text-zinc-400 leading-relaxed">
              Create an organization to collaborate with your team, assign security analyst roles, and share threat intelligence telemetry.
            </p>

            <form onSubmit={handleCreateOrg} className="mt-4 space-y-4">
              <div>
                <label className="block text-xs font-medium uppercase tracking-wider text-zinc-400 mb-1.5">
                  Organization Name
                </label>
                <input
                  type="text"
                  required
                  value={newOrgName}
                  onChange={(e) => setNewOrgName(e.target.value)}
                  placeholder="e.g. Acme Cyber SOC"
                  className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-500 outline-none focus:border-red-500/60"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setCreateModalOpen(false)}
                  className="rounded-lg px-3 py-2 text-xs font-medium text-zinc-400 hover:bg-zinc-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingOrg}
                  className="flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white hover:bg-red-500 disabled:opacity-50"
                >
                  {creatingOrg ? <Loader2 className="h-4 w-4 animate-spin" /> : <Building2 className="h-4 w-4" />}
                  <span>Create Workspace</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
