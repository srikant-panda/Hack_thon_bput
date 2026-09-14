import { KeyRound } from 'lucide-react';
import PageHeader from '../components/common/PageHeader';

/**
 * ORG-2: Account Takeover — Coming Soon placeholder (disabled state).
 * Per the Excalidraw spec: no functionality; manual review via admins.
 */
export default function OrgAccountTakeover() {
  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <PageHeader
        title="Account Takeover"
        description="Identity-compromise detection across org authentication events."
      />
      <div className="flex flex-col items-center rounded-xl border border-zinc-800 bg-zinc-900/50 p-10 text-center opacity-80">
        <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-zinc-800 ring-1 ring-zinc-700">
          <KeyRound className="h-8 w-8 text-zinc-600" />
        </div>
        <span className="mt-4 rounded bg-zinc-800 px-3 py-1 font-mono text-[11px] uppercase tracking-wider text-zinc-400">
          Coming Soon
        </span>
        <h2 className="mt-3 text-base font-bold text-zinc-200">Account Takeover analysis is coming soon.</h2>
        <p className="mt-2 max-w-md text-xs leading-relaxed text-zinc-500">
          This module is not yet available for organization workspaces. Contact your admin for
          manual review of suspicious authentication activity — auth-shaped logs ingested through
          the gateway are still auto-analyzed and visible on the Live Log Analysis page.
        </p>
      </div>
    </div>
  );
}
