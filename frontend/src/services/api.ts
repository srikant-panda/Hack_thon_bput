import type {
  ActionExecution,
  ActionListResponse,
  Alert,
  AnalysisResult,
  AuditLog,
  DashboardSummary,
  EnforcementPolicy,
  Incident,
  IncidentStatus,
  PolicyListResponse,
  PolicyUpdatePayload,
  ResponseActionCatalog,
  ResponseExecution,
  Severity,
  ThreatModule,
  User,
  Organization,
  OrganizationMember,
  OrganizationRole,
  UserContext,

  EmailConnectorAccount,
  EmailProviderRegistryEntry,
  ConnectorOperationLog,
  MailMessageSummary,
  ScanResult,
  MessageAnalysis,
  ConnectorSettings,
  QuarantinedItem,
  BlockedSender,
  SecurityEventRecord,
  QuarantineReview,
  NotificationLogEntry,
  TrustedSender,
  ReleaseAndTrustResult,} from '../types';
import * as mockApi from './mockApi';
import { db, addAuditLog } from './mockData';
import { ApiError, apiFetch } from './http';
import {
  mapAlert,
  mapAnalysisResult,
  mapAuditLog,
  mapDashboardSummary,
  mapIncident,
  mapResponseCatalog,
  mapResponseExecution,
} from './mappers';
import { useAuthStore } from '../store/authStore';

// ---------------------------------------------------------------------------
// Service facade — the ONLY module pages import.
// USE_MOCK=true  -> delegate to the in-browser mock API (no behaviour change).
// USE_MOCK=false -> live Supabase Auth + real backend at VITE_API_BASE_URL.
// Raw log listing endpoints (login events, network flows, API logs) have no
// backend counterpart yet and still fall back to the mock layer with a
// console warning.
// ---------------------------------------------------------------------------

const USE_MOCK = import.meta.env.VITE_USE_MOCK !== 'false';

function notYetIntegrated<T>(functionName: string, mockCall: () => Promise<T>): Promise<T> {
  console.warn('[CYBERGUARD] endpoint not yet integrated, using mock:', functionName);
  return mockCall();
}

export async function login(email: string, password: string): Promise<{ user: User; token: string }> {
  if (USE_MOCK) return mockApi.mockLogin(email, password);
  // Real login is performed by the auth store via Supabase Auth.
  await useAuthStore.getState().login(email, password);
  const state = useAuthStore.getState();
  return { user: state.user as User, token: state.accessToken ?? '' };
}

export async function loginWithOAuth(provider: 'google' | 'github'): Promise<void> {
  await useAuthStore.getState().loginWithOAuth(provider);
}

export async function logout(): Promise<void> {
  if (USE_MOCK) {
    await useAuthStore.getState().logout();
    return;
  }
  await useAuthStore.getState().logout();
}

export async function getUserProfile(): Promise<UserContext> {
  if (USE_MOCK) return mockApi.mockGetUserContext();
  return apiFetch('/auth/me');
}

export async function getDashboardSummary(): Promise<DashboardSummary> {
  if (USE_MOCK) return mockApi.mockGetDashboardSummary();
  const row = await apiFetch('/dashboard/summary');
  return mapDashboardSummary(row);
}

export async function listAlerts(filters?: {
  severity?: Severity;
  module?: ThreatModule;
  status?: string;
  search?: string;
  limit?: number;
  offset?: number;
}): Promise<Alert[]> {
  if (USE_MOCK) return mockApi.mockListAlerts(filters);
  const params = new URLSearchParams();
  if (filters?.severity) params.set('severity', filters.severity);
  if (filters?.module) params.set('module', filters.module);
  if (filters?.status) params.set('status', filters.status);
  if (filters?.search) params.set('search', filters.search);
  if (filters?.limit !== undefined) params.set('limit', String(filters.limit));
  if (filters?.offset !== undefined) params.set('offset', String(filters.offset));
  const rows = await apiFetch(`/alerts?${params.toString()}`);
  return (Array.isArray(rows) ? rows : []).map(mapAlert);
}

export async function getAlert(id: string): Promise<Alert | null> {
  if (USE_MOCK) return mockApi.mockGetAlert(id);
  try {
    const row = await apiFetch(`/alerts/${id}`);
    return row ? mapAlert(row) : null;
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}

export async function updateAlertStatus(id: string, status: Alert['status']): Promise<Alert> {
  if (USE_MOCK) {
    const alert = db.alerts.find((a) => a.id === id);
    if (!alert) throw new Error(`Alert ${id} not found`);
    alert.status = status;
    addAuditLog({
      userId: 'USR-001',
      userName: 'admin@cyberguard.local',
      action: 'UPDATE_ALERT_STATUS',
      resource: id,
      details: `Alert status changed to ${status}`,
    });
    return alert;
  }
  const row = await apiFetch(`/alerts/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  });
  return mapAlert(row);
}

// ---------------------------------------------------------------------------
// Analysis pipelines (Part 3-5 backend endpoints)
// ---------------------------------------------------------------------------

export async function analyzeEmail(sender: string, subject: string, body: string): Promise<AnalysisResult> {
  if (USE_MOCK) return mockApi.mockAnalyzeEmail(sender, subject, body);
  const row = await apiFetch('/analysis/email', {
    method: 'POST',
    body: JSON.stringify({ sender, subject, body }),
  });
  return mapAnalysisResult(row);
}

export async function analyzeUrl(url: string): Promise<AnalysisResult> {
  if (USE_MOCK) return mockApi.mockAnalyzeUrl(url);
  const row = await apiFetch('/analysis/url', { method: 'POST', body: JSON.stringify({ url }) });
  return mapAnalysisResult(row);
}

export async function analyzeImpersonation(message: string, claimedIdentity: string): Promise<AnalysisResult> {
  if (USE_MOCK) return mockApi.mockAnalyzeImpersonation(message, claimedIdentity);
  const row = await apiFetch('/analysis/impersonation', {
    method: 'POST',
    body: JSON.stringify({ message, claimed_identity: claimedIdentity }),
  });
  return mapAnalysisResult(row);
}

export async function analyzeMedia(file: File): Promise<AnalysisResult> {
  if (USE_MOCK) return mockApi.mockAnalyzeMedia({ name: file.name, size: file.size, type: file.type });
  // Multipart upload: no Content-Type header so the browser sets the boundary.
  const formData = new FormData();
  formData.append('file', file);
  const row = await apiFetch('/analysis/media', { method: 'POST', body: formData });
  return mapAnalysisResult(row);
}

export async function analyzeAuthLog(
  events: Array<{ user: string; ip: string; location: string; device: string; status: string; timestamp: string }>
): Promise<AnalysisResult> {
  if (USE_MOCK) return mockApi.mockAnalyzeAuthLog(events);
  const row = await apiFetch('/analysis/account-takeover', {
    method: 'POST',
    body: JSON.stringify({ events }),
  });
  return mapAnalysisResult(row);
}

export async function analyzeNetworkFlow(
  flows: Array<{ sourceIp: string; destIp: string; port: number; bytesOut: number; protocol: string }>,
  apiLogs: Array<{ endpoint: string; method: string; statusCode: number; sourceIp: string }> = []
): Promise<AnalysisResult> {
  if (USE_MOCK) return mockApi.mockAnalyzeNetworkFlow(flows);
  const row = await apiFetch('/analysis/network', {
    method: 'POST',
    body: JSON.stringify({ flows, api_logs: apiLogs }),
  });
  return mapAnalysisResult(row);
}

export async function analyzeApiLog(
  logs: Array<{ endpoint: string; method: string; statusCode: number; sourceIp: string }>
): Promise<AnalysisResult> {
  if (USE_MOCK) return mockApi.mockAnalyzeApiLog(logs);
  const row = await apiFetch('/analysis/network', {
    method: 'POST',
    body: JSON.stringify({ flows: [], api_logs: logs }),
  });
  return mapAnalysisResult(row);
}

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

export async function listIncidents(): Promise<Incident[]> {
  if (USE_MOCK) return mockApi.mockListIncidents();
  const rows = await apiFetch('/incidents');
  return (Array.isArray(rows) ? rows : []).map(mapIncident);
}

export async function getIncident(id: string): Promise<Incident | null> {
  if (USE_MOCK) return mockApi.mockGetIncident(id);
  try {
    const row = await apiFetch(`/incidents/${id}`);
    return row ? mapIncident(row) : null;
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}

export async function createIncident(alertId: string): Promise<Incident> {
  if (USE_MOCK) return mockApi.mockCreateIncident(alertId);
  // The incidents endpoint derives its title/severity from the linked alert.
  const alert = await getAlert(alertId).catch(() => null);
  const row = await apiFetch('/incidents', {
    method: 'POST',
    body: JSON.stringify({
      title: alert?.title ?? `Incident from alert ${alertId}`,
      severity: alert?.severity ?? 'medium',
      linked_alert_ids: [alertId],
    }),
  });
  return mapIncident(row);
}

export async function updateIncidentStatus(id: string, status: IncidentStatus): Promise<Incident> {
  if (USE_MOCK) return mockApi.mockUpdateIncidentStatus(id, status);
  const row = await apiFetch(`/incidents/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  });
  return mapIncident(row);
}

export async function assignIncident(id: string, analyst: string): Promise<Incident> {
  if (USE_MOCK) return mockApi.mockAssignIncident(id, analyst);
  const row = await apiFetch(`/incidents/${id}/assign`, {
    method: 'PATCH',
    body: JSON.stringify({ assigned_to: analyst }),
  });
  return mapIncident(row);
}

export async function escalateIncident(id: string, reason?: string): Promise<Incident> {
  if (USE_MOCK) return mockApi.mockEscalateIncident(id);
  const row = await apiFetch(`/incidents/${id}/escalate`, {
    method: 'POST',
    body: JSON.stringify({ reason: reason ?? 'Escalated from the SOC console' }),
  });
  return mapIncident(row);
}

// ---------------------------------------------------------------------------
// Response actions
// ---------------------------------------------------------------------------

export async function listResponseCatalog(): Promise<ResponseActionCatalog[]> {
  if (USE_MOCK) return mockApi.mockListResponseCatalog();
  const rows = await apiFetch('/responses/catalog');
  return (Array.isArray(rows) ? rows : []).map(mapResponseCatalog);
}

export async function executeResponse(actionId: string, target: string, approved: boolean): Promise<ResponseExecution> {
  if (USE_MOCK) return mockApi.mockExecuteResponse(actionId, target, approved);
  const row = await apiFetch('/responses/execute', {
    method: 'POST',
    body: JSON.stringify({ catalog_id: actionId, target, approved }),
  });
  return mapResponseExecution(row);
}

export async function listResponseHistory(): Promise<ResponseExecution[]> {
  if (USE_MOCK) return mockApi.mockListResponseHistory();
  const rows = await apiFetch('/responses/history');
  return (Array.isArray(rows) ? rows : []).map(mapResponseExecution);
}

// ---------------------------------------------------------------------------
// Audit logs
// ---------------------------------------------------------------------------

export async function listAuditLogs(actorType?: string): Promise<AuditLog[]> {
  if (USE_MOCK) return mockApi.mockListAuditLogs();
  const suffix = actorType ? `&actor_type=${encodeURIComponent(actorType)}` : '';
  const rows = await apiFetch(`/audit/logs?limit=200${suffix}`);
  return (Array.isArray(rows) ? rows : []).map(mapAuditLog);
}

export async function listLoginEvents(): Promise<import('../types').LoginEvent[]> {
  if (USE_MOCK) return mockApi.mockListLoginEvents();
  return notYetIntegrated('listLoginEvents', () => mockApi.mockListLoginEvents());
}

export async function listNetworkFlows(): Promise<import('../types').NetworkFlow[]> {
  if (USE_MOCK) return mockApi.mockListNetworkFlows();
  return notYetIntegrated('listNetworkFlows', () => mockApi.mockListNetworkFlows());
}

export async function listApiLogs(): Promise<import('../types').ApiLogEntry[]> {
  if (USE_MOCK) return mockApi.mockListApiLogs();
  return notYetIntegrated('listApiLogs', () => mockApi.mockListApiLogs());
}

// ---------------------------------------------------------------------------
// SOC assistant
// ---------------------------------------------------------------------------

export async function assistantChat(message: string): Promise<string> {
  if (USE_MOCK) return mockApi.mockAssistantChat(message);
  const row = await apiFetch('/assistant/chat', {
    method: 'POST',
    body: JSON.stringify({ message }),
  });
  const record = row && typeof row === 'object' ? (row as Record<string, unknown>) : {};
  return String(record.reply ?? 'The assistant is temporarily unable to generate a response.');
}

export async function addAlert(alert: Alert): Promise<void> {
  if (USE_MOCK) return mockApi.mockAddAlert(alert);
  return notYetIntegrated('addAlert', async () => mockApi.mockAddAlert(alert));
}

// ---------------------------------------------------------------------------
// Organizations & Team Member Management
// ---------------------------------------------------------------------------

export async function listOrganizations(): Promise<Organization[]> {
  if (USE_MOCK) {
    const ctx = await mockApi.mockGetUserContext();
    return ctx.organizations;
  }
  const rows = await apiFetch('/organizations');
  return Array.isArray(rows) ? (rows as Organization[]) : [];
}

export async function createOrganization(name: string): Promise<Organization> {
  if (USE_MOCK) {
    const newOrg: Organization = {
      id: `org-${Date.now()}`,
      name,
      slug: name.toLowerCase().replace(/\s+/g, '-'),
      is_personal: false,
      role: 'admin',
      created_at: new Date().toISOString(),
    };
    return newOrg;
  }
  const org = await apiFetch('/organizations', {
    method: 'POST',
    body: JSON.stringify({ name }),
  });
  await useAuthStore.getState().fetchUserContext();
  return org as Organization;
}

export async function getOrganization(orgId: string): Promise<Organization> {
  if (USE_MOCK) {
    const ctx = await mockApi.mockGetUserContext();
    const found = ctx.organizations.find((o) => o.id === orgId);
    if (found) return found;
    return {
      id: ctx.active_organization.id,
      name: ctx.active_organization.name,
      slug: 'active-org',
      is_personal: ctx.active_organization.is_personal,
      role: ctx.active_organization.role,
    };
  }
  const org = await apiFetch(`/organizations/${orgId}`);
  return org as Organization;
}

export async function listOrganizationMembers(orgId: string): Promise<OrganizationMember[]> {
  if (USE_MOCK) {
    return [
      {
        id: 'mem-1',
        organizationId: orgId,
        userId: 'u-1',
        email: 'admin@cyberguard.local',
        fullName: 'Lead Analyst (Admin)',
        role: 'admin',
        joinedAt: new Date(Date.now() - 86400000 * 30).toISOString(),
      },
      {
        id: 'mem-2',
        organizationId: orgId,
        userId: 'u-2',
        email: 'analyst@cyberguard.local',
        fullName: 'Security Analyst',
        role: 'analyst',
        joinedAt: new Date(Date.now() - 86400000 * 14).toISOString(),
      },
      {
        id: 'mem-3',
        organizationId: orgId,
        userId: 'u-3',
        email: 'auditor@cyberguard.local',
        fullName: 'SOC Auditor',
        role: 'viewer',
        joinedAt: new Date(Date.now() - 86400000 * 5).toISOString(),
      },
    ];
  }
  const rows = await apiFetch(`/organizations/${orgId}/members`);
  if (!Array.isArray(rows)) return [];
  return rows.map((r: any) => ({
    id: r.id,
    organizationId: r.organization_id,
    userId: r.user_id,
    email: r.email,
    fullName: r.full_name,
    role: r.role as OrganizationRole,
    joinedAt: r.joined_at,
  }));
}

export async function addOrganizationMember(
  orgId: string,
  email: string,
  role: OrganizationRole
): Promise<OrganizationMember> {
  if (USE_MOCK) {
    return {
      id: `mem-${Date.now()}`,
      organizationId: orgId,
      userId: `user-${Date.now()}`,
      email,
      fullName: email.split('@')[0],
      role,
      joinedAt: new Date().toISOString(),
    };
  }
  const res = await apiFetch(`/organizations/${orgId}/members`, {
    method: 'POST',
    body: JSON.stringify({ email, role }),
  });
  return {
    id: res.id,
    organizationId: res.organization_id,
    userId: res.user_id,
    email: res.email,
    fullName: res.full_name,
    role: res.role as OrganizationRole,
    joinedAt: res.joined_at,
  };
}

export async function updateOrganizationMemberRole(
  orgId: string,
  targetUserId: string,
  role: OrganizationRole
): Promise<OrganizationMember> {
  if (USE_MOCK) {
    return {
      id: `mem-${targetUserId}`,
      organizationId: orgId,
      userId: targetUserId,
      role,
      joinedAt: new Date().toISOString(),
    };
  }
  const res = await apiFetch(`/organizations/${orgId}/members/${targetUserId}`, {
    method: 'PATCH',
    body: JSON.stringify({ role }),
  });
  return {
    id: res.id,
    organizationId: res.organization_id,
    userId: res.user_id,
    email: res.email,
    fullName: res.full_name,
    role: res.role as OrganizationRole,
    joinedAt: res.joined_at,
  };
}

export async function removeOrganizationMember(orgId: string, targetUserId: string): Promise<void> {
  if (USE_MOCK) return;
  await apiFetch(`/organizations/${orgId}/members/${targetUserId}`, {
    method: 'DELETE',
  });
}

export async function switchOrganization(orgId: string): Promise<void> {
  await useAuthStore.getState().switchOrganization(orgId);
}

// ---------------------------------------------------------------------------
// Admin User Management
// ---------------------------------------------------------------------------

export interface AdminUser {
  id: string;
  email: string | null;
  full_name: string | null;
  role: 'viewer' | 'analyst' | 'admin';
  created_at: string | null;
}

export async function listAdminUsers(): Promise<AdminUser[]> {
  if (USE_MOCK) {
    await new Promise((r) => setTimeout(r, 200));
    return [
      { id: 'USR-001', email: 'admin@cyberguard.local', full_name: 'SOC Administrator', role: 'admin', created_at: new Date('2026-01-05').toISOString() },
      { id: 'USR-002', email: 'analyst@cyberguard.local', full_name: 'Demo Analyst', role: 'analyst', created_at: new Date('2026-01-06').toISOString() },
      { id: 'USR-003', email: 'viewer@cyberguard.local', full_name: 'Demo Viewer', role: 'viewer', created_at: new Date('2026-01-07').toISOString() },
    ];
  }
  const rows = await apiFetch('/admin/users');
  return (Array.isArray(rows) ? rows : []) as AdminUser[];
}

export async function updateUserRole(
  userId: string,
  role: 'viewer' | 'analyst' | 'admin'
): Promise<AdminUser> {
  if (USE_MOCK) {
    await new Promise((r) => setTimeout(r, 200));
    return { id: userId, email: null, full_name: null, role, created_at: null };
  }
  const row = await apiFetch(`/admin/users/${userId}/role`, {
    method: 'PATCH',
    body: JSON.stringify({ role }),
  });
  return row as AdminUser;
}


// ---------------------------------------------------------------------------
// Email Connectors (Phase 1-2: Gmail only). Mock mode returns static, honest
// demo data — never a fake Gmail connection.
// ---------------------------------------------------------------------------

export async function listConnectorCapabilities(): Promise<EmailProviderRegistryEntry[]> {
  if (USE_MOCK) {
    return [
      {
        provider: 'gmail',
        display_name: 'Gmail',
        status: 'coming_soon',
        capabilities: null,
        detail: 'DEMO MODE — connector actions are simulated/unavailable',
      },
      {
        provider: 'outlook',
        display_name: 'Outlook',
        status: 'coming_soon',
        capabilities: null,
        detail: 'Microsoft Graph connector arrives with the Orgs Phase',
      },
      {
        provider: 'yahoo',
        display_name: 'Yahoo Mail',
        status: 'unsupported',
        capabilities: null,
        detail: 'Yahoo Mail has no third-party OAuth API',
      },
      {
        provider: 'icloud',
        display_name: 'iCloud Mail',
        status: 'unsupported',
        capabilities: null,
        detail: 'iCloud Mail has no third-party OAuth API',
      },
    ];
  }
  const res = await apiFetch('/connectors/capabilities');
  return res.items as EmailProviderRegistryEntry[];
}

export async function listEmailConnectors(): Promise<EmailConnectorAccount[]> {
  if (USE_MOCK) return []; // Demo mode: no connectors, no fake Gmail account.
  const res = await apiFetch('/connectors');
  return res.items as EmailConnectorAccount[];
}

export async function authorizeGmailConnector(): Promise<string> {
  if (USE_MOCK) {
    throw new Error('DEMO MODE — connector actions are simulated/unavailable');
  }
  const res = await apiFetch('/connectors/gmail/authorize', { method: 'POST', body: '{}' });
  return res.authorization_url as string;
}

export async function testEmailConnector(
  id: string,
): Promise<{ ok: boolean; email_address?: string; messages_total?: number; message?: string }> {
  if (USE_MOCK) {
    throw new Error('DEMO MODE — connector actions are simulated/unavailable');
  }
  return (await apiFetch(`/connectors/${id}/test`, { method: 'POST' })) as {
    ok: boolean;
    message?: string;
  };
}

export async function disconnectEmailConnector(id: string): Promise<void> {
  if (USE_MOCK) {
    throw new Error('DEMO MODE — connector actions are simulated/unavailable');
  }
  await apiFetch(`/connectors/${id}`, { method: 'DELETE' });
}

export async function listConnectorOperations(): Promise<ConnectorOperationLog[]> {
  if (USE_MOCK) return [];
  const res = await apiFetch('/connectors/operations');
  return res.items as ConnectorOperationLog[];
}


// --- Mailbox scanning (Phase 3) — analysis only; enforcement is Phase 4 ---

export async function listConnectorMessages(
  connectorId: string,
  limit = 20,
): Promise<MailMessageSummary[]> {
  if (USE_MOCK) return []; // Demo mode has no real mailbox.
  return (await apiFetch(`/connectors/${connectorId}/messages?limit=${limit}`)) as MailMessageSummary[];
}

export async function scanConnectorMessages(
  connectorId: string,
  body: { message_ids?: string[]; scan_recent?: number },
): Promise<ScanResult[]> {
  if (USE_MOCK) {
    throw new Error('DEMO MODE — mailbox scanning requires a real connected mailbox');
  }
  return (await apiFetch(`/connectors/${connectorId}/scan`, {
    method: 'POST',
    body: JSON.stringify(body),
  })) as ScanResult[];
}

export async function getMessageAnalysis(
  connectorId: string,
  messageId: string,
): Promise<MessageAnalysis> {
  if (USE_MOCK) {
    throw new Error('DEMO MODE — mailbox scanning requires a real connected mailbox');
  }
  return (await apiFetch(`/connectors/${connectorId}/messages/${messageId}/analysis`)) as MessageAnalysis;
}


// --- Enforcement (Phase 4) — real provider-backed actions ---

export async function getConnectorSettings(connectorId: string): Promise<ConnectorSettings> {
  if (USE_MOCK) {
    return {
      connector_id: connectorId,
      quarantine_expiry_hours: 24,
      permanent_delete_enabled: false,
      auto_quarantine_enabled: true,
      updated_at: null,
    };
  }
  return (await apiFetch(`/connectors/${connectorId}/settings`)) as ConnectorSettings;
}

export async function updateConnectorSettings(
  connectorId: string,
  patch: {
    quarantine_expiry_hours?: number | null;
    expiry_mode?: 'hours' | 'manual';
    permanent_delete_enabled?: boolean;
    auto_quarantine_enabled?: boolean;
  },
): Promise<ConnectorSettings> {
  if (USE_MOCK) {
    return getConnectorSettings(connectorId);
  }
  return (await apiFetch(`/connectors/${connectorId}/settings`, {
    method: 'PUT',
    body: JSON.stringify(patch),
  })) as ConnectorSettings;
}

export async function listQuarantined(): Promise<QuarantinedItem[]> {
  if (USE_MOCK) return []; // Demo mode: no real mailbox actions exist.
  const res = await apiFetch('/enforcement/quarantine');
  return res.items as QuarantinedItem[];
}

export async function releaseQuarantined(itemId: string): Promise<string> {
  if (USE_MOCK) throw new Error('DEMO MODE — enforcement actions are simulated/unavailable');
  const res = await apiFetch(`/enforcement/quarantine/${itemId}/release`, { method: 'POST' });
  return res.status as string;
}

export async function deleteQuarantined(itemId: string): Promise<{ status: string; message?: string }> {
  if (USE_MOCK) throw new Error('DEMO MODE — enforcement actions are simulated/unavailable');
  return (await apiFetch(`/enforcement/quarantine/${itemId}/delete`, { method: 'POST' })) as {
    status: string;
    message?: string;
  };
}

export async function listBlockedSenders(): Promise<BlockedSender[]> {
  if (USE_MOCK) return [];
  const res = await apiFetch('/enforcement/blocked-senders');
  return res.items as BlockedSender[];
}

export async function unblockSender(blockId: string): Promise<string> {
  if (USE_MOCK) throw new Error('DEMO MODE — enforcement actions are simulated/unavailable');
  const res = await apiFetch(`/enforcement/blocked-senders/${blockId}/release`, { method: 'POST' });
  return res.status as string;
}

export async function releaseAndTrustQuarantined(itemId: string): Promise<ReleaseAndTrustResult> {
  if (USE_MOCK) throw new Error('DEMO MODE — enforcement actions are simulated/unavailable');
  return (await apiFetch(`/enforcement/quarantine/${itemId}/release-and-trust`, {
    method: 'POST',
  })) as ReleaseAndTrustResult;
}

export async function listTrustedSenders(): Promise<TrustedSender[]> {
  if (USE_MOCK) return [];
  const res = await apiFetch('/enforcement/trusted-senders');
  return res.items as TrustedSender[];
}

export async function trustSender(senderEmail: string, reason: string): Promise<TrustedSender> {
  if (USE_MOCK) throw new Error('DEMO MODE — enforcement actions are simulated/unavailable');
  return (await apiFetch('/enforcement/trusted-senders', {
    method: 'POST',
    body: JSON.stringify({ sender_email: senderEmail, reason }),
  })) as TrustedSender;
}

export async function removeTrustedSender(senderId: string): Promise<string> {
  if (USE_MOCK) throw new Error('DEMO MODE — enforcement actions are simulated/unavailable');
  const res = await apiFetch(`/enforcement/trusted-senders/${senderId}`, { method: 'DELETE' });
  return res.status as string;
}


// --- Security history (Phase 5) ---

export interface SecurityHistoryFilters {
  event_type?: string;
  actor_type?: string;
  severity?: string;
  sender_email?: string;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
}

export async function listSecurityHistory(
  filters: SecurityHistoryFilters = {},
): Promise<{ items: SecurityEventRecord[]; total: number; limit: number; offset: number }> {
  if (USE_MOCK) return { items: [], total: 0, limit: filters.limit ?? 50, offset: filters.offset ?? 0 };
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(filters)) {
    if (v !== undefined && v !== null && v !== '') params.set(k, String(v));
  }
  return (await apiFetch(`/security-history?${params.toString()}`)) as {
    items: SecurityEventRecord[];
    total: number;
    limit: number;
    offset: number;
  };
}

export async function getQuarantineReview(itemId: string): Promise<QuarantineReview> {
  if (USE_MOCK) throw new Error('DEMO MODE — history requires a real backend');
  return (await apiFetch(`/quarantine/${itemId}/review`)) as QuarantineReview;
}

export async function keepQuarantined(itemId: string): Promise<string> {
  if (USE_MOCK) throw new Error('DEMO MODE — enforcement actions are simulated/unavailable');
  const res = await apiFetch(`/enforcement/quarantine/${itemId}/keep`, { method: 'POST' });
  return res.status as string;
}

// --- Notifications (Phase 7) ---

export async function listNotificationLogs(): Promise<NotificationLogEntry[]> {
  if (USE_MOCK) return [];
  const res = await apiFetch('/notifications');
  return res.items as NotificationLogEntry[];
}

export async function updateNotificationEmail(email: string | null): Promise<string | null> {
  if (USE_MOCK) return email;
  const res = await apiFetch('/auth/notification-email', {
    method: 'PUT',
    body: JSON.stringify({ notification_email: email }),
  });
  return res.notification_email as string | null;
}

export function isMockMode(): boolean {
  return USE_MOCK;
}

export { mockApi };

// ---------------------------------------------------------------------------
// Dual-Mode Enforcement — action executions, quarantine, blocklist, policies
// ---------------------------------------------------------------------------

export async function listActions(params?: {
  status?: string;
  action_type?: string;
  module?: string;
  severity?: string;
  page?: number;
  page_size?: number;
}): Promise<ActionListResponse> {
  if (USE_MOCK) return mockApi.mockListActions(params);
  const query = new URLSearchParams();
  if (params?.status) query.set('status', params.status);
  if (params?.action_type) query.set('action_type', params.action_type);
  if (params?.module) query.set('module', params.module);
  if (params?.severity) query.set('severity', params.severity);
  if (params?.page) query.set('page', String(params.page));
  if (params?.page_size) query.set('page_size', String(params.page_size));
  return apiFetch(`/actions?${query.toString()}`);
}

export async function getAction(id: string): Promise<ActionExecution> {
  if (USE_MOCK) return mockApi.mockGetAction(id);
  return apiFetch(`/actions/${id}`);
}

export async function approveAction(id: string, comment?: string): Promise<ActionExecution> {
  if (USE_MOCK) return mockApi.mockApproveAction(id, comment);
  return apiFetch(`/actions/${id}/approve`, {
    method: 'POST',
    body: JSON.stringify({ comment: comment ?? null }),
  });
}

export async function rejectAction(id: string, reason: string): Promise<ActionExecution> {
  if (USE_MOCK) return mockApi.mockRejectAction(id, reason);
  return apiFetch(`/actions/${id}/reject`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });
}

export async function listQuarantine(page?: number, pageSize?: number): Promise<ActionListResponse> {
  if (USE_MOCK) return mockApi.mockListQuarantine(page, pageSize);
  const query = new URLSearchParams();
  if (page) query.set('page', String(page));
  if (pageSize) query.set('page_size', String(pageSize));
  return apiFetch(`/actions/quarantine/list?${query.toString()}`);
}

export async function releaseQuarantine(id: string): Promise<ActionExecution> {
  if (USE_MOCK) return mockApi.mockReleaseQuarantine(id);
  return apiFetch(`/actions/quarantine/${id}/release`, { method: 'POST' });
}

export async function listBlocklist(page?: number, pageSize?: number): Promise<ActionListResponse> {
  if (USE_MOCK) return mockApi.mockListBlocklist(page, pageSize);
  const query = new URLSearchParams();
  if (page) query.set('page', String(page));
  if (pageSize) query.set('page_size', String(pageSize));
  return apiFetch(`/actions/blocklist/list?${query.toString()}`);
}

export async function unblockItem(id: string): Promise<ActionExecution> {
  if (USE_MOCK) return mockApi.mockUnblockItem(id);
  return apiFetch(`/actions/blocklist/${id}/unblock`, { method: 'POST' });
}

export async function listPolicies(): Promise<PolicyListResponse> {
  if (USE_MOCK) return mockApi.mockListPolicies();
  return apiFetch('/policies');
}

export async function getPolicy(id: string): Promise<EnforcementPolicy> {
  if (USE_MOCK) return mockApi.mockGetPolicy(id);
  return apiFetch(`/policies/${id}`);
}

export async function updatePolicy(id: string, updates: PolicyUpdatePayload): Promise<EnforcementPolicy> {
  if (USE_MOCK) return mockApi.mockUpdatePolicy(id, updates);
  return apiFetch(`/policies/${id}`, {
    method: 'PUT',
    body: JSON.stringify(updates),
  });
}

export async function activatePolicy(id: string): Promise<EnforcementPolicy> {
  if (USE_MOCK) return mockApi.mockActivatePolicy(id);
  return apiFetch(`/policies/${id}/activate`, { method: 'POST' });
}

// ---------------------------------------------------------------------------
// Dead Letter Queue (DLQ) Ops (RT-10)
// ---------------------------------------------------------------------------

export async function getDlqStats(): Promise<import('../types').DlqStats> {
  if (USE_MOCK) {
    return {
      total_dead_letter: 3,
      by_job_type: { gmail_sync: 2, email_fetch: 1, email_analysis: 0 },
      oldest_age_hours: 4.5,
    };
  }
  return apiFetch('/dlq/stats');
}

export async function getDlqJobs(params?: {
  job_type?: string;
  from_date?: string;
  to_date?: string;
  owner_user_id?: string;
  limit?: number;
  offset?: number;
}): Promise<import('../types').DlqJobsResponse> {
  if (USE_MOCK) {
    const mockJobs = [
      {
        job_id: 'job-dlq-001',
        job_type: 'gmail_sync',
        owner_user_id: 'usr_admin',
        payload: { user_id: 'usr_admin', account_id: 'acc_123', correlation_id: 'corr-001' },
        error: 'GmailAuthError: 401 Unauthorized - user revoked OAuth token',
        retry_count: 0,
        created_at: new Date(Date.now() - 4.5 * 3600 * 1000).toISOString(),
        updated_at: new Date(Date.now() - 4.5 * 3600 * 1000).toISOString(),
        retry_history: [
          { attempt: 1, error: 'GmailAuthError: 401 Unauthorized', timestamp: new Date(Date.now() - 4.5 * 3600 * 1000).toISOString() }
        ]
      },
      {
        job_id: 'job-dlq-002',
        job_type: 'email_fetch',
        owner_user_id: 'usr_analyst',
        payload: { user_id: 'usr_analyst', message_id: 'msg_456', correlation_id: 'corr-002' },
        error: 'MIMECorruptionError: Corrupt boundary delimiters in RFC 2822 payload',
        retry_count: 0,
        created_at: new Date(Date.now() - 2.1 * 3600 * 1000).toISOString(),
        updated_at: new Date(Date.now() - 2.1 * 3600 * 1000).toISOString(),
        retry_history: [
          { attempt: 1, error: 'MIMECorruptionError: Corrupt boundary delimiters', timestamp: new Date(Date.now() - 2.1 * 3600 * 1000).toISOString() }
        ]
      },
      {
        job_id: 'job-dlq-003',
        job_type: 'gmail_sync',
        owner_user_id: 'usr_admin',
        payload: { user_id: 'usr_admin', account_id: 'acc_789', correlation_id: 'corr-003' },
        error: 'GmailRateLimitError: 429 Too Many Requests - quota exceeded',
        retry_count: 5,
        created_at: new Date(Date.now() - 1.2 * 3600 * 1000).toISOString(),
        updated_at: new Date(Date.now() - 0.2 * 3600 * 1000).toISOString(),
        retry_history: [
          { attempt: 1, error: 'GmailRateLimitError 429', timestamp: new Date(Date.now() - 1.2 * 3600 * 1000).toISOString() },
          { attempt: 5, error: 'GmailRateLimitError 429: max retries exceeded', timestamp: new Date(Date.now() - 0.2 * 3600 * 1000).toISOString() }
        ]
      }
    ];
    let filtered = mockJobs;
    if (params?.job_type) {
      filtered = filtered.filter(j => j.job_type === params.job_type);
    }
    return {
      jobs: filtered,
      total: filtered.length,
      limit: params?.limit ?? 50,
      offset: params?.offset ?? 0
    };
  }
  const query = new URLSearchParams();
  if (params?.job_type) query.set('job_type', params.job_type);
  if (params?.from_date) query.set('from_date', params.from_date);
  if (params?.to_date) query.set('to_date', params.to_date);
  if (params?.owner_user_id) query.set('owner_user_id', params.owner_user_id);
  if (params?.limit !== undefined) query.set('limit', String(params.limit));
  if (params?.offset !== undefined) query.set('offset', String(params.offset));
  const qs = query.toString();
  return apiFetch(`/dlq/jobs${qs ? `?${qs}` : ''}`);
}

export async function getDlqJob(jobId: string): Promise<import('../types').DlqJob> {
  if (USE_MOCK) {
    const list = await getDlqJobs();
    const found = list.jobs.find(j => j.job_id === jobId);
    if (found) return found;
    throw new Error('Job not found in mock DLQ');
  }
  return apiFetch(`/dlq/jobs/${jobId}`);
}

export async function retryDlqJob(jobId: string): Promise<{ success: boolean; message: string }> {
  if (USE_MOCK) {
    return { success: true, message: `Job ${jobId} reset to queued and re-enqueued` };
  }
  return apiFetch(`/dlq/jobs/${jobId}/retry`, { method: 'POST' });
}

export async function deleteDlqJob(jobId: string): Promise<{ success: boolean; message: string }> {
  if (USE_MOCK) {
    return { success: true, message: `Job ${jobId} soft-deleted` };
  }
  return apiFetch(`/dlq/jobs/${jobId}`, { method: 'DELETE' });
}
