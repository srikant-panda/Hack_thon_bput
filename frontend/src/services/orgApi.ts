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
