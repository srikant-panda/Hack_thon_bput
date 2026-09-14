import { Link, useParams } from 'react-router-dom';
import {
  ArrowRight,
  Ban,
  KeyRound,
  Mail,
  Network,
  ScrollText,
  Settings,
  ShieldAlert,
  Terminal,
  UserX,
  Video,
} from 'lucide-react';
import PageHeader from '../components/common/PageHeader';

const MODULES = [
  {
    to: '/phishing',
    label: 'Phishing',
    description: 'Email phishing detection with verbose, org-scoped verdicts.',
    icon: Mail,
    enabled: true,
  },
  {
    to: '/url-analysis',
    label: 'URL',
    description: 'Reputation-aware malicious URL analysis for org traffic.',
    icon: Network,
    enabled: true,
  },
  {
    to: '/deepfake',
    label: 'Deepfake',
    description: 'Media forensics and synthetic-media detection.',
    icon: Video,
    enabled: true,
  },
  {
    to: '/impersonation',
    label: 'Impersonation',
    description: 'Brand and executive impersonation / BEC detection.',
    icon: UserX,
    enabled: true,
  },
  {
    to: '/log-analysis',
    label: 'Live Log Analysis',
    description: 'Splunk-style stream of gateway-ingested logs, auto-analyzed.',
    icon: Terminal,
    enabled: true,
  },
  {
    to: '/account-takeover',
    label: 'Account Takeover',
    description: 'Coming soon.',
    icon: KeyRound,
    enabled: false,
  },
];

/**
 * ORG-1: organization-scoped dashboard shell.
 * The detection modules are fed by gateway payloads and mail-server streams
 * (no manual paste-boxes); live detector views land with ORG-2.
 */
export default function OrganizationDashboard() {
  const { orgId } = useParams<{ orgId: string }>();

  const curlExample = `curl -X POST \\${'\n'}  http://localhost:8000/api/v1/org/${orgId ?? '{org_id}'}/gateway \\${'\n'}  -H "org_authorization: cg_live_xxx" \\${'\n'}  -H "Content-Type: application/json" \\${'\n'}  -d '{"action": "scan_email", "data": {"sender": "attacker@example.com", "subject": "Urgent: Verify your account", "body": "Click here to verify..."}}'`;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <PageHeader
          title="Organization Dashboard"
          description="Org-scoped threat modules fed by the gateway and mail-server streams."
        />
        <div className="flex items-center gap-2">
          {orgId && (
            <Link
              to={`/org/${orgId}/settings`}
              className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 px-3.5 py-2 text-xs font-semibold text-zinc-200 transition hover:border-zinc-500"
            >
              <Settings className="h-4 w-4" />
              <span>Org Settings</span>
            </Link>
          )}
          <Link
            to="/org/create"
            className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 px-3.5 py-2 text-xs font-semibold text-zinc-200 transition hover:border-zinc-500"
          >
            <span>New Organization</span>
          </Link>
        </div>
      </div>

      {/* Module grid */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {MODULES.map((m) => {
          const Icon = m.icon;
          const inner = (
            <>
              <div className="flex items-center justify-between">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-red-500/10 ring-1 ring-red-500/30">
                  <Icon className={`h-5 w-5 ${m.enabled ? 'text-red-400' : 'text-zinc-600'}`} />
                </div>
                {m.enabled ? (
                  <ArrowRight className="h-4 w-4 text-zinc-600 transition group-hover:translate-x-0.5 group-hover:text-zinc-300" />
                ) : (
                  <span className="rounded bg-zinc-800 px-2 py-0.5 font-mono text-[10px] uppercase text-zinc-500">
                    Coming Soon
                  </span>
                )}
              </div>
              <h3 className={`mt-3 text-sm font-bold ${m.enabled ? 'text-zinc-100' : 'text-zinc-500'}`}>
                {m.label}
              </h3>
              <p className="mt-1 text-xs leading-relaxed text-zinc-500">{m.description}</p>
            </>
          );
          return m.enabled ? (
            <Link
              key={m.label}
              to={m.to}
              className="group rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur transition hover:border-zinc-600"
            >
              {inner}
            </Link>
          ) : (
            <div
              key={m.label}
              aria-disabled
              className="cursor-not-allowed rounded-xl border border-zinc-800/60 bg-zinc-900/50 p-5 opacity-70"
            >
              {inner}
            </div>
          );
        })}
      </div>

      {/* Gateway integration panel */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur">
        <div className="mb-3 flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
          <ScrollText className="h-4 w-4 text-red-400" />
          <span>Gateway Endpoint (server-to-server)</span>
        </div>
        <p className="mb-3 text-xs leading-relaxed text-zinc-400">
          Create an API key in <strong className="text-zinc-200">Org Settings</strong>, then POST
          events to the organization-scoped gateway. Supported actions:{' '}
          <code className="font-mono text-zinc-300">scan_email</code>,{' '}
          <code className="font-mono text-zinc-300">scan_url</code>,{' '}
          <code className="font-mono text-zinc-300">ingest_log</code>.
        </p>
        <pre className="overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-950 p-4 font-mono text-[11px] leading-relaxed text-zinc-300">
          {curlExample}
        </pre>
        <div className="mt-3 flex items-start gap-2 text-[11px] text-zinc-500">
          <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            Requests with a missing/invalid key return 401; a key used against a different
            organization returns 403. All ingested data is RLS-isolated per organization.
          </span>
        </div>
      </div>

      {/* Non-goals note (ORG-1 scope) */}
      <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3.5 text-xs leading-relaxed text-amber-300">
        <Ban className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        <span>
          <strong>Scope note:</strong> org features are fed by gateway payloads and mail-server
          streams — there are no manual paste-boxes. Mail-server connectors (ORG-3), notification
          groups (ORG-4) and the live org-scoped detector views (ORG-2) ship in the next phases.
        </span>
      </div>
    </div>
  );
}
