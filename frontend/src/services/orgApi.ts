/**
 * ORG-1 Foundation API: organizations with name salting, API key management,
 * org settings, members (RBAC), and the org-scoped gateway.
 *
 * Endpoints are always-on server-side (unlike the frozen /organizations
 * router). See backend/docs/org_foundation.md.
 */

import { apiFetch } from './http';

// --- Types ---

export interface OrgCreated {
  id: string;
  name: string;
  displayName?: string | null;
  slug: string;
  isPersonal: boolean;
  ownerId: string;
  role?: string | null;
}

export interface OrgApiKey {
  id: string;
  name: string;
  keyPrefix: string;
  lastUsedAt: string | null;
  expiresAt: string | null;
  status: string;
  createdAt?: string;
}

export interface OrgApiKeyCreated extends OrgApiKey {
  /** Plaintext — returned EXACTLY ONCE by the create endpoint. */
  key: string;
}

export interface OrgSetting {
  key: string;
  value: Record<string, unknown>;
  updatedAt?: string;
}

export interface OrgMember {
  id: string;
  organizationId: string;
  userId: string;
  email?: string | null;
  fullName?: string | null;
  role: 'admin' | 'analyst' | 'viewer';
  joinedAt?: string;
}

export interface GatewayResult {
  status: string;
  action: string;
  result: Record<string, unknown>;
}

// --- Organizations ---

export function createOrg(name: string): Promise<OrgCreated> {
  return apiFetch('/orgs', { method: 'POST', body: JSON.stringify({ name }) });
}

// --- API keys ---

export function listApiKeys(orgId: string): Promise<OrgApiKey[]> {
  return apiFetch(`/orgs/${orgId}/api-keys`);
}

export function createApiKey(
  orgId: string,
  name: string,
  expiresAt?: string | null,
): Promise<OrgApiKeyCreated> {
  return apiFetch(`/orgs/${orgId}/api-keys`, {
    method: 'POST',
    body: JSON.stringify({ name, expires_at: expiresAt ?? null }),
  });
}

export function revokeApiKey(orgId: string, keyId: string): Promise<OrgApiKey> {
  return apiFetch(`/orgs/${orgId}/api-keys/${keyId}`, { method: 'DELETE' });
}

// --- Settings ---

export function listSettings(orgId: string): Promise<OrgSetting[]> {
  return apiFetch(`/orgs/${orgId}/settings`);
}

export function upsertSetting(
  orgId: string,
  key: string,
  value: Record<string, unknown>,
): Promise<OrgSetting> {
  return apiFetch(`/orgs/${orgId}/settings/${encodeURIComponent(key)}`, {
    method: 'PUT',
    body: JSON.stringify({ value }),
  });
}

// --- Members ---

export function listMembers(orgId: string): Promise<OrgMember[]> {
  return apiFetch(`/orgs/${orgId}/members`);
}

export function addMember(
  orgId: string,
  email: string,
  role: OrgMember['role'],
): Promise<OrgMember> {
  return apiFetch(`/orgs/${orgId}/members`, {
    method: 'POST',
    body: JSON.stringify({ email, role }),
  });
}

export function updateMemberRole(
  orgId: string,
  userId: string,
  role: OrgMember['role'],
): Promise<OrgMember> {
  return apiFetch(`/orgs/${orgId}/members/${userId}`, {
    method: 'PATCH',
    body: JSON.stringify({ role }),
  });
}

export function removeMember(orgId: string, userId: string): Promise<{ message: string }> {
  return apiFetch(`/orgs/${orgId}/members/${userId}`, { method: 'DELETE' });
}

// --- Gateway (used for diagnostics / integration snippets) ---

export function callGateway(
  orgId: string,
  apiKey: string,
  action: 'scan_email' | 'scan_url' | 'ingest_log',
  data: Record<string, unknown>,
): Promise<GatewayResult> {
  return fetch(
    `${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1'}/org/${orgId}/gateway`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', org_authorization: apiKey },
      body: JSON.stringify({ action, data }),
    },
  ).then(async (res) => {
    if (!res.ok) throw new Error(`Gateway error ${res.status}`);
    return res.json();
  });
}

// ---------------------------------------------------------------------------
// ORG-2: dashboards + live log analysis
// ---------------------------------------------------------------------------

export type DashboardFeature = 'phishing' | 'url' | 'deepfake' | 'impersonation';
export type LogType = 'auth' | 'network' | 'app';
export type LogAction =
  | 'block_ip'
  | 'revoke_session'
  | 'escalate_incident'
  | 'mark_safe'
  | 'isolate_host';

export interface DashboardSummary {
  organization_id: string;
  total_scans: number;
  threats_detected: number;
  quarantined_emails: number;
  blocked_senders: number;
  critical_alerts: number;
  last_scan_at: string | null;
}

export interface FeatureScanRow {
  alert_id: string;
  timestamp: string | null;
  severity: string;
  score: number;
  title: string;
  target: string | null;
  indicators: Array<Record<string, unknown>>;
  explanation: string | null;
  action_taken: string | null;
}

export interface FeatureDashboard {
  feature: string;
  total: number;
  limit: number;
  offset: number;
  rows: FeatureScanRow[];
}

export interface OrgLogEvent {
  id: string;
  log_type: LogType;
  severity: string;
  raw_data: Record<string, unknown>;
  analysis_result: Record<string, unknown>;
  manual_action_taken: string | null;
  acted_by: string | null;
  acted_at: string | null;
  created_at: string | null;
}

export interface DashboardFeedParams {
  limit?: number;
  offset?: number;
  severity?: string | null;
  from_date?: string | null;
  to_date?: string | null;
}

function qs(params: Record<string, string | number | null | undefined>): string {
  const pairs = Object.entries(params)
    .filter(([, v]) => v !== null && v !== undefined && v !== '')
    .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`);
  return pairs.length ? `?${pairs.join('&')}` : '';
}

export function getDashboardSummary(orgId: string): Promise<DashboardSummary> {
  return apiFetch(`/org/${orgId}/dashboard/summary`);
}

export function getFeatureDashboard(
  orgId: string,
  feature: DashboardFeature,
  params: DashboardFeedParams = {},
): Promise<FeatureDashboard> {
  return apiFetch(
    `/org/${orgId}/dashboard/${feature}${qs({
      limit: params.limit,
      offset: params.offset,
      severity: params.severity,
      from_date: params.from_date,
      to_date: params.to_date,
    })}`,
  );
}

export function getLogStream(
  orgId: string,
  params: { limit?: number; severity?: string | null; log_type?: string | null } = {},
): Promise<OrgLogEvent[]> {
  return apiFetch(`/org/${orgId}/logs/stream${qs({ ...params })}`);
}

export function takeLogAction(
  orgId: string,
  logId: string,
  action: LogAction,
  target?: string,
  note?: string,
): Promise<{ log_id: string; action: string; taken_by: string; taken_at: string }> {
  return apiFetch(`/org/${orgId}/logs/${logId}/action`, {
    method: 'POST',
    body: JSON.stringify({ action, target, note }),
  });
}

// ---------------------------------------------------------------------------
// ORG-3: org mail server connectors (server-to-server infrastructure)
// ---------------------------------------------------------------------------

export type MailProviderType = 'google_workspace' | 'microsoft_365' | 'imap_smtp';

export interface MailServer {
  id: string;
  name: string;
  provider_type: MailProviderType;
  status: 'connected' | 'disconnected' | 'error';
  last_connected_at: string | null;
  last_error: string | null;
  has_credentials: boolean;
  created_at?: string;
}

export interface MailServerLog {
  id: string;
  mail_server_id: string;
  log_type: 'connection' | 'scan' | 'quarantine' | 'error';
  message: string;
  metadata: Record<string, unknown> | null;
  created_at: string | null;
}

export interface MailServerCredentialDraft {
  service_account_key?: string;
  delegated_user?: string;
  client_id?: string;
  client_secret?: string;
  tenant_id?: string;
  host?: string;
  port?: number;
  username?: string;
  password?: string;
}

export function listMailServers(orgId: string): Promise<MailServer[]> {
  return apiFetch(`/org/${orgId}/mail-servers`);
}

export function createMailServer(
  orgId: string,
  name: string,
  provider_type: MailProviderType,
  credentials?: MailServerCredentialDraft,
): Promise<MailServer> {
  return apiFetch(`/org/${orgId}/mail-servers`, {
    method: 'POST',
    body: JSON.stringify({ name, provider_type, credentials }),
  });
}

export function connectMailServer(
  orgId: string,
  serverId: string,
  credentials?: MailServerCredentialDraft,
): Promise<{ id: string; status: string }> {
  return apiFetch(`/org/${orgId}/mail-servers/${serverId}/connect`, {
    method: 'POST',
    body: JSON.stringify(credentials ? { credentials } : {}),
  });
}

export function disconnectMailServer(orgId: string, serverId: string): Promise<{ id: string; status: string }> {
  return apiFetch(`/org/${orgId}/mail-servers/${serverId}/disconnect`, { method: 'POST', body: JSON.stringify({}) });
}

export function deleteMailServer(orgId: string, serverId: string): Promise<{ message: string }> {
  return apiFetch(`/org/${orgId}/mail-servers/${serverId}`, { method: 'DELETE' });
}

export function listMailServerLogs(
  orgId: string,
  serverId: string,
  params: { limit?: number; log_type?: string | null; from_date?: string | null; to_date?: string | null } = {},
): Promise<MailServerLog[]> {
  return apiFetch(`/org/${orgId}/mail-servers/${serverId}/logs${qs({ ...params })}`);
}

export function getMailServerSettings(
  orgId: string,
  serverId: string,
): Promise<{ mail_server_id: string; settings: Record<string, unknown> }> {
  return apiFetch(`/org/${orgId}/mail-servers/${serverId}/settings`);
}

export function updateMailServerSettings(
  orgId: string,
  serverId: string,
  settings: Record<string, unknown>,
): Promise<{ mail_server_id: string; settings: Record<string, unknown> }> {
  return apiFetch(`/org/${orgId}/mail-servers/${serverId}/settings`, {
    method: 'PUT',
    body: JSON.stringify({ settings }),
  });
}
