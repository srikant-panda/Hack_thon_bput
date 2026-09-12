import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  AlertTriangle,
  CheckCircle2,
  Cloud,
  ExternalLink,
  Loader2,
  Mail,
  PlugZap,
  RefreshCw,
  Unplug,
  XCircle,
} from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import * as api from '../services/api';
import type { EmailConnectorAccount, EmailProviderRegistryEntry } from '../types';

const PROVIDER_ICONS: Record<string, typeof Mail> = {
  gmail: Mail,
  outlook: Mail,
  yahoo: Mail,
  icloud: Mail,
};

const STATUS_STYLES: Record<string, string> = {
  connected: 'bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/30',
  reauth_required: 'bg-amber-500/10 text-amber-400 ring-1 ring-amber-500/30',
  revoked: 'bg-zinc-800 text-zinc-400 ring-1 ring-zinc-700',
  error: 'bg-red-500/10 text-red-400 ring-1 ring-red-500/30',
};

const PROVIDER_STATUS_STYLES: Record<string, string> = {
  enabled: 'bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/30',
  coming_soon: 'bg-zinc-800 text-zinc-400 ring-1 ring-zinc-700',
  unsupported: 'bg-zinc-900 text-zinc-600 ring-1 ring-zinc-800',
};

function formatWhen(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

export default function EmailConnectors() {
  const isMockMode = api.isMockMode();
  const [searchParams, setSearchParams] = useSearchParams();

  const [registry, setRegistry] = useState<EmailProviderRegistryEntry[]>([]);
  const [connectors, setConnectors] = useState<EmailConnectorAccount[]>([]);
  const [loading, setLoading] = useState(true);
  const [authorizing, setAuthorizing] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [disconnectingId, setDisconnectingId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; ok: boolean; message: string } | null>(null);

  const oauthStatus = searchParams.get('status');
  const oauthReason = searchParams.get('reason');
  const oauthProvider = searchParams.get('connected');

  const load = useCallback(async () => {
    setLoading(true);
    setActionError(null);
    try {
      const [caps, conns] = await Promise.all([api.listConnectorCapabilities(), api.listEmailConnectors()]);
      setRegistry(caps);
      setConnectors(conns);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to load connectors');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // Clear the OAuth banner params once dismissed (any interaction).
  const dismissBanner = useCallback(() => {
    if (searchParams.get('connected')) {
      searchParams.delete('connected');
      searchParams.delete('status');
      searchParams.delete('reason');
      setSearchParams(searchParams, { replace: true });
    }
  }, [searchParams, setSearchParams]);

  const handleConnectGmail = async () => {
    setAuthorizing(true);
    setActionError(null);
    try {
      const url = await api.authorizeGmailConnector();
      window.location.href = url; // navigate to the Google consent screen
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to start Gmail authorization');
      setAuthorizing(false);
    }
  };

  const handleTest = async (connector: EmailConnectorAccount) => {
    setTestingId(connector.id);
    setTestResult(null);
    setActionError(null);
    try {
      const result = await api.testEmailConnector(connector.id);
      const email = (result as { email_address?: string }).email_address;
      setTestResult({
        id: connector.id,
        ok: result.ok,
        message: result.ok
          ? email
            ? `Connection OK for ${email}`
            : 'Connection OK'
          : result.message ?? 'Connection test failed',
      });
      await load();
    } catch (err) {
      setTestResult({
        id: connector.id,
        ok: false,
        message: err instanceof Error ? err.message : 'Connection test failed',
      });
    } finally {
      setTestingId(null);
    }
  };

  const handleDisconnect = async (connector: EmailConnectorAccount) => {
    setDisconnectingId(connector.id);
    setActionError(null);
    setTestResult(null);
    try {
      await api.disconnectEmailConnector(connector.id);
      await load();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to disconnect');
    } finally {
      setDisconnectingId(null);
    }
  };

  const gmailEntry = registry.find((r) => r.provider === 'gmail');
  const otherProviders = registry.filter((r) => r.provider !== 'gmail');
  const gmailEnabled = gmailEntry?.status === 'enabled';

  return (
    <div className="space-y-6" onClick={() => oauthStatus && dismissBanner()}>
      <PageHeader
        title="Email Connectors"
        description="Connect your mailbox so CYBERGUARD can scan authorized messages and perform real provider-backed actions."
      />

      {/* OAuth result banner */}
      {oauthProvider && (
        <div
          className={`flex items-start gap-2 rounded-lg border p-3.5 text-sm ${
            oauthStatus === 'success'
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
              : 'border-red-500/40 bg-red-500/10 text-red-300'
          }`}
        >
          {oauthStatus === 'success' ? (
            <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0 text-emerald-400" />
          ) : (
            <XCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-red-400" />
          )}
          <div>
            <p className="font-semibold">
              {oauthStatus === 'success'
                ? `${oauthProvider === 'gmail' ? 'Gmail' : oauthProvider} connected successfully`
                : `${oauthProvider === 'gmail' ? 'Gmail' : oauthProvider} connection failed`}
            </p>
            {oauthStatus !== 'success' && (
              <p className="mt-0.5 text-xs opacity-80">
                Reason: {oauthReason ?? 'unknown'} — check the operation log below or try connecting again.
              </p>
            )}
          </div>
        </div>
      )}

      {/* Mock-mode honesty badge */}
      {isMockMode && (
        <div className="flex items-center gap-2 rounded-lg border border-zinc-700/60 bg-zinc-800/40 px-3.5 py-2.5 text-xs text-zinc-300">
          <AlertTriangle className="h-4 w-4 text-amber-400" />
          <span className="font-mono font-bold tracking-wider">DEMO MODE — connector actions are simulated/unavailable</span>
        </div>
      )}

      {actionError && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/10 px-3.5 py-2.5 text-sm text-red-300">
          <AlertTriangle className="h-4 w-4 text-red-400" />
          {actionError}
        </div>
      )}

      {/* Provider cards */}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {[gmailEntry, ...otherProviders].filter(Boolean).map((entry) => {
          const Icon = PROVIDER_ICONS[entry!.provider] ?? Cloud;
          const isGmail = entry!.provider === 'gmail';
          return (
            <div
              key={entry!.provider}
              className="flex flex-col rounded-2xl border border-zinc-800 bg-zinc-900/90 p-5 shadow-sm backdrop-blur"
            >
              <div className="flex items-center justify-between">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-zinc-950 ring-1 ring-zinc-800">
                  <Icon className="h-5 w-5 text-zinc-300" />
                </div>
                <span
                  className={`rounded px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${
                    PROVIDER_STATUS_STYLES[entry!.status] ?? PROVIDER_STATUS_STYLES.coming_soon
                  }`}
                >
                  {entry!.status.replace('_', ' ')}
                </span>
              </div>
              <h3 className="mt-3 text-sm font-semibold text-zinc-100">{entry!.display_name}</h3>
              <p className="mt-1 flex-1 text-xs leading-relaxed text-zinc-500">
                {entry!.detail || (entry!.status === 'enabled' ? 'Ready to connect with mailbox modify access.' : '')}
              </p>
              {isGmail && (
                <button
                  type="button"
                  onClick={handleConnectGmail}
                  disabled={authorizing || !gmailEnabled || isMockMode}
                  className="mt-4 flex items-center justify-center gap-2 rounded-lg bg-red-600 py-2 text-xs font-bold text-white shadow-lg shadow-red-600/20 transition hover:bg-red-500 disabled:cursor-not-allowed disabled:opacity-50"
                  title={gmailEnabled ? 'Connect your Gmail mailbox' : entry!.detail || 'Gmail connector is not configured yet'}
                >
                  {authorizing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <PlugZap className="h-3.5 w-3.5" />}
                  Connect Gmail
                </button>
              )}
            </div>
          );
        })}
      </div>

      {/* Connected accounts */}
      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/90 shadow-sm backdrop-blur">
        <div className="flex items-center justify-between border-b border-zinc-800 px-5 py-4">
          <h2 className="text-sm font-semibold text-zinc-100">Connected Accounts</h2>
          <button
            type="button"
            onClick={load}
            className="flex items-center gap-1.5 text-xs text-zinc-400 transition hover:text-red-400"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center gap-2 px-5 py-10 text-sm text-zinc-500">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading connectors…
          </div>
        ) : connectors.length === 0 ? (
          <div className="px-5 py-10 text-center text-sm text-zinc-500">
            No mailboxes connected yet. {gmailEnabled ? 'Connect Gmail above to get started.' : 'Gmail needs backend configuration (Google OAuth client + CONNECTOR_TOKEN_KEY) before it can be connected.'}
          </div>
        ) : (
          <div className="divide-y divide-zinc-800">
            {connectors.map((connector) => (
              <div key={connector.id} className="flex flex-col gap-3 px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-semibold text-zinc-100">{connector.provider_email}</span>
                    <span className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-zinc-400">
                      {connector.provider}
                    </span>
                    <span className={`rounded px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${STATUS_STYLES[connector.status] ?? STATUS_STYLES.error}`}>
                      {connector.status.replace('_', ' ')}
                    </span>
                  </div>
                  <p className="mt-1 truncate font-mono text-[11px] text-zinc-500">
                    Scopes: {connector.scopes.length ? connector.scopes.join(', ') : '—'} · Last test: {formatWhen(connector.last_test_at)}
                  </p>
                  {connector.last_error && (
                    <p className="mt-1 text-xs text-red-400">{connector.last_error}</p>
                  )}
                  {testResult?.id === connector.id && (
                    <p className={`mt-1 text-xs ${testResult.ok ? 'text-emerald-400' : 'text-red-400'}`}>
                      {testResult.ok ? '✔ ' : '✖ '}
                      {testResult.message}
                    </p>
                  )}
                </div>
                <div className="flex flex-shrink-0 items-center gap-2">
                  <button
                    type="button"
                    onClick={() => handleTest(connector)}
                    disabled={testingId === connector.id || isMockMode}
                    className="flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-1.5 text-xs font-semibold text-zinc-200 transition hover:border-zinc-700 hover:bg-zinc-800/60 disabled:opacity-50"
                  >
                    {testingId === connector.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ExternalLink className="h-3.5 w-3.5" />}
                    Test
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDisconnect(connector)}
                    disabled={disconnectingId === connector.id || isMockMode}
                    className="flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-semibold text-red-400 transition hover:bg-red-500/20 disabled:opacity-50"
                  >
                    {disconnectingId === connector.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Unplug className="h-3.5 w-3.5" />}
                    Disconnect
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <p className="text-[11px] leading-relaxed text-zinc-600">
        Gmail access uses CYBERGUARD's own Google OAuth client with the
        gmail.modify scope. Tokens are encrypted at rest on the server and are
        never sent to the browser. Phase 3 adds mailbox scanning; quarantine and
        sender actions follow in Phase 4.
      </p>
    </div>
  );
}
