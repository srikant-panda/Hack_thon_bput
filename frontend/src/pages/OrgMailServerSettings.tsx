import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Loader2, Save, Settings2 } from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import { useUiStore } from '../store/uiStore';
import * as orgApi from '../services/orgApi';

/**
 * ORG-3: per-mail-server settings — each mail server has its own
 * configuration (scan cadence, quarantine behavior, auto-blocking).
 */
export default function OrgMailServerSettings() {
  const { orgId, serverId } = useParams<{ orgId: string; serverId: string }>();
  const addToast = useUiStore((s) => s.addToast);
  const [server, setServer] = useState<orgApi.MailServer | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [scanInterval, setScanInterval] = useState(300);
  const [quarantineEnabled, setQuarantineEnabled] = useState(true);
  const [autoBlock, setAutoBlock] = useState(false);
  const [quarantineExpiry, setQuarantineExpiry] = useState(24);

  const load = useCallback(async () => {
    if (!orgId || !serverId) return;
    try {
      const [settingsRes, servers] = await Promise.all([
        orgApi.getMailServerSettings(orgId, serverId),
        orgApi.listMailServers(orgId),
      ]);
      const s = settingsRes.settings;
      if (typeof s.scan_interval_seconds === 'number') setScanInterval(s.scan_interval_seconds);
      if (typeof s.quarantine_enabled === 'boolean') setQuarantineEnabled(s.quarantine_enabled);
      if (typeof s.auto_block_malicious_senders === 'boolean') setAutoBlock(s.auto_block_malicious_senders);
      if (typeof s.quarantine_expiry_hours === 'number') setQuarantineExpiry(s.quarantine_expiry_hours);
      setServer(servers.find((x) => x.id === serverId) ?? null);
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to load settings', 'high');
    } finally {
      setLoading(false);
    }
  }, [orgId, serverId, addToast]);

  useEffect(() => {
    load();
  }, [load]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId || !serverId) return;
    setSaving(true);
    try {
      await orgApi.updateMailServerSettings(orgId, serverId, {
        scan_interval_seconds: scanInterval,
        quarantine_enabled: quarantineEnabled,
        auto_block_malicious_senders: autoBlock,
        quarantine_expiry_hours: quarantineExpiry,
      });
      addToast('Mail server settings saved', 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to save settings', 'high');
    } finally {
      setSaving(false);
    }
  };

  if (!orgId || !serverId) return <div className="p-6 text-sm text-zinc-400">No mail server selected.</div>;

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <PageHeader
          title={`Settings — ${server?.name ?? 'Mail Server'}`}
          description="This server's own configuration; changes never affect other mail servers."
        />
        <Link
          to={`/org/${orgId}/mail-servers`}
          className="self-start rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-200 transition hover:border-zinc-500"
        >
          All servers
        </Link>
      </div>

      {loading ? (
        <div className="flex items-center gap-2 py-8 text-xs text-zinc-500">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading…
        </div>
      ) : (
        <form onSubmit={handleSave} className="space-y-5 rounded-xl border border-zinc-800 bg-zinc-900/90 p-6 backdrop-blur">
          <div className="flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
            <Settings2 className="h-4 w-4 text-red-400" />
            <span>Scan & Quarantine Configuration</span>
          </div>

          <div>
            <label className="mb-1.5 block text-xs font-semibold text-zinc-300">Scan interval (seconds)</label>
            <input
              type="number"
              min={30}
              max={86400}
              value={scanInterval}
              onChange={(e) => setScanInterval(Number(e.target.value))}
              className="w-40 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 outline-none focus:border-red-500/60"
            />
            <p className="mt-1 text-[11px] text-zinc-500">How often CYBERGUARD pulls new messages from this server (default 300).</p>
          </div>

          <div className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-950/60 p-3.5">
            <div>
              <p className="text-xs font-semibold text-zinc-200">Quarantine enabled</p>
              <p className="mt-0.5 text-[11px] text-zinc-500">Move flagged messages out of inboxes on this server.</p>
            </div>
            <button
              type="button"
              onClick={() => setQuarantineEnabled((v) => !v)}
              className={`relative h-6 w-11 rounded-full transition ${quarantineEnabled ? 'bg-emerald-600' : 'bg-zinc-700'}`}
            >
              <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition ${quarantineEnabled ? 'left-[22px]' : 'left-0.5'}`} />
            </button>
          </div>

          <div className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-950/60 p-3.5">
            <div>
              <p className="text-xs font-semibold text-zinc-200">Auto-block malicious senders</p>
              <p className="mt-0.5 text-[11px] text-zinc-500">Block senders whose messages score critical on this server.</p>
            </div>
            <button
              type="button"
              onClick={() => setAutoBlock((v) => !v)}
              className={`relative h-6 w-11 rounded-full transition ${autoBlock ? 'bg-red-600' : 'bg-zinc-700'}`}
            >
              <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition ${autoBlock ? 'left-[22px]' : 'left-0.5'}`} />
            </button>
          </div>

          <div>
            <label className="mb-1.5 block text-xs font-semibold text-zinc-300">Quarantine expiry (hours)</label>
            <input
              type="number"
              min={1}
              max={720}
              value={quarantineExpiry}
              onChange={(e) => setQuarantineExpiry(Number(e.target.value))}
              className="w-40 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 outline-none focus:border-red-500/60"
            />
            <p className="mt-1 text-[11px] text-zinc-500">Quarantined messages auto-release after this many hours (default 24).</p>
          </div>

          <button
            type="submit"
            disabled={saving}
            className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-red-600/20 transition hover:bg-red-500 disabled:opacity-50"
          >
            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            <span>Save Settings</span>
          </button>
        </form>
      )}
    </div>
  );
}
