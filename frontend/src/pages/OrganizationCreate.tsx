import { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { ArrowRight, Building2, Info, Loader2 } from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import { useUiStore } from '../store/uiStore';
import * as orgApi from '../services/orgApi';

/**
 * ORG-1: create an organization (admin flow).
 * Applies to both email/password and OAuth accounts — the backend salts the
 * name on conflict ("Acme Corp" -> "Acme Corp-2") and the creator becomes the
 * org admin.
 */
export default function OrganizationCreate() {
  const navigate = useNavigate();
  const location = useLocation();
  const addToast = useUiStore((s) => s.addToast);

  // Org signup on the Login page forwards the chosen name via router state.
  const [name, setName] = useState<string>(
    () => (location.state as { name?: string } | null)?.name ?? ''
  );
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<orgApi.OrgCreated | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || creating) return;
    setCreating(true);
    try {
      const org = await orgApi.createOrg(name.trim());
      setCreated(org);
      addToast(`Organization created: ${org.name}`, 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to create organization', 'high');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <PageHeader
        title="Create Organization"
        description="Set up a team workspace with role-based access (admin, analyst, viewer) and server-to-server API keys."
      />

      {!created ? (
        <form
          onSubmit={handleSubmit}
          className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-6 backdrop-blur"
        >
          <label className="mb-2 block font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
            Organization Name
          </label>
          <input
            type="text"
            required
            maxLength={100}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Acme Corp"
            className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2.5 text-sm text-zinc-100 placeholder-zinc-500 outline-none focus:border-red-500/60"
          />
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 text-xs leading-relaxed text-zinc-400">
            <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-zinc-500" />
            <span>
              If the name is already taken it is salted automatically (e.g. "Acme Corp" →
              "Acme Corp-2"). You become the organization <strong className="text-zinc-200">admin</strong>.
            </span>
          </div>
          <button
            type="submit"
            disabled={creating || !name.trim()}
            className="mt-5 inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-red-600/20 transition hover:bg-red-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {creating ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                <span>Creating…</span>
              </>
            ) : (
              <>
                <Building2 className="h-4 w-4" />
                <span>Create Organization</span>
              </>
            )}
          </button>
        </form>
      ) : (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-6 backdrop-blur">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-red-500/10 ring-1 ring-red-500/30">
              <Building2 className="h-6 w-6 text-red-400" />
            </div>
            <div>
              <h2 className="text-base font-bold text-zinc-100">
                Organization created: {created.name}
              </h2>
              <p className="font-mono text-xs text-zinc-500">
                {created.displayName && created.displayName !== created.name
                  ? `Original name: ${created.displayName} • `
                  : ''}
                ID: {created.id}
              </p>
            </div>
          </div>
          <p className="mt-4 text-xs leading-relaxed text-zinc-400">
            You are the organization admin. Next: manage API keys and members in the
            organization settings, then connect your mail server or SIEM to the
            organization gateway.
          </p>
          <button
            onClick={() => navigate(`/org/${created.id}/dashboard`)}
            className="mt-5 inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-red-600/20 transition hover:bg-red-500"
          >
            <span>Go to Organization Dashboard</span>
            <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      )}
    </div>
  );
}
