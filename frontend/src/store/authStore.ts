import { create } from 'zustand';
import { getSupabase } from '../lib/supabaseClient';
import * as mockApi from '../services/mockApi';
import type { Organization, User } from '../types';

// Mock mode stays fully available behind VITE_USE_MOCK so the demo keeps
// working without a Supabase project or backend.
const USE_MOCK = import.meta.env.VITE_USE_MOCK !== 'false';
const MOCK_STORAGE_KEY = 'cyberguard_auth';
const ACTIVE_ORG_KEY = 'cyberguard_active_org';
const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

interface AuthState {
  user: User | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  /** True once hydrate() has finished (session restored or absent). */
  hydrated: boolean;
  organizations: Organization[];
  activeOrganization: Organization | null;
  activeOrganizationId: string | null;

  login: (email: string, password: string) => Promise<void>;
  loginWithOAuth: (provider: 'google' | 'github') => Promise<void>;
  logout: () => Promise<void>;
  hydrate: () => Promise<void>;
  fetchUserContext: () => Promise<void>;
  switchOrganization: (orgId: string) => Promise<void>;
  getToken: () => string | null;
  setAccessToken: (token: string | null) => void;
}

function toUser(supabaseUser: {
  id: string;
  email?: string | null;
  user_metadata?: Record<string, any>;
}): User {
  const email = supabaseUser.email ?? '';
  const fullName = supabaseUser.user_metadata?.full_name || supabaseUser.user_metadata?.name;
  return {
    id: supabaseUser.id,
    name: fullName || email.split('@')[0] || 'SOC Analyst',
    email,
    role: 'analyst',
    avatar: supabaseUser.user_metadata?.avatar_url,
  };
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  accessToken: null,
  isAuthenticated: false,
  hydrated: false,
  organizations: [],
  activeOrganization: null,
  activeOrganizationId: localStorage.getItem(ACTIVE_ORG_KEY),

  login: async (email, password) => {
    if (USE_MOCK) {
      const { user, token } = await mockApi.mockLogin(email, password);
      localStorage.setItem(MOCK_STORAGE_KEY, JSON.stringify({ user, token }));
      set({ user, accessToken: token, isAuthenticated: true, hydrated: true });
      await get().fetchUserContext();
      return;
    }

    const { data, error } = await getSupabase().auth.signInWithPassword({ email, password });
    if (error || !data.session) {
      // Surface the Supabase message, e.g. "Invalid login credentials".
      throw new Error(error?.message ?? 'Login failed');
    }
    set({
      user: toUser(data.session.user),
      accessToken: data.session.access_token,
      isAuthenticated: true,
      hydrated: true,
    });
    await get().fetchUserContext();
  },

  loginWithOAuth: async (provider: 'google' | 'github') => {
    if (USE_MOCK) {
      const { user, token } = await mockApi.mockLoginOAuth(provider);
      localStorage.setItem(MOCK_STORAGE_KEY, JSON.stringify({ user, token }));
      set({ user, accessToken: token, isAuthenticated: true, hydrated: true });
      await get().fetchUserContext();
      return;
    }

    const { error } = await getSupabase().auth.signInWithOAuth({
      provider,
      options: {
        redirectTo: `${window.location.origin}/dashboard`,
      },
    });
    if (error) {
      throw new Error(error.message ?? `Failed to sign in with ${provider}`);
    }
  },

  logout: async () => {
    if (!USE_MOCK) {
      await getSupabase().auth.signOut().catch(() => undefined);
    }
    localStorage.removeItem(MOCK_STORAGE_KEY);
    localStorage.removeItem(ACTIVE_ORG_KEY);
    set({
      user: null,
      accessToken: null,
      isAuthenticated: false,
      organizations: [],
      activeOrganization: null,
      activeOrganizationId: null,
    });
  },

  fetchUserContext: async () => {
    if (USE_MOCK) {
      const ctx = await mockApi.mockGetUserContext();
      const storedOrgId = localStorage.getItem(ACTIVE_ORG_KEY);
      const active = ctx.organizations.find((o) => o.id === storedOrgId) || ctx.active_organization;
      set({
        organizations: ctx.organizations,
        activeOrganization: active as Organization,
        activeOrganizationId: active?.id ?? null,
      });
      return;
    }

    const token = get().accessToken;
    if (!token) return;

    try {
      const res = await fetch(`${BASE_URL}/auth/me`, {
        headers: {
          Authorization: `Bearer ${token}`,
          ...(get().activeOrganizationId ? { 'X-Organization-Id': get().activeOrganizationId! } : {}),
        },
      });
      if (res.ok) {
        const data = await res.json();
        const orgs: Organization[] = data.organizations || [];
        const storedOrgId = localStorage.getItem(ACTIVE_ORG_KEY);
        const active = orgs.find((o) => o.id === storedOrgId) || (data.active_organization as Organization);
        set({
          organizations: orgs,
          activeOrganization: active || null,
          activeOrganizationId: active?.id ?? null,
          user: get().user
            ? {
                ...get().user!,
                role: data.active_role || get().user!.role,
                name: data.full_name || get().user!.name,
              }
            : null,
        });
        if (active?.id) {
          localStorage.setItem(ACTIVE_ORG_KEY, active.id);
        }
      }
    } catch (err) {
      console.error('Failed to fetch user context:', err);
    }
  },

  switchOrganization: async (orgId: string) => {
    if (USE_MOCK) {
      const org = get().organizations.find((o) => o.id === orgId) || null;
      if (org) {
        localStorage.setItem(ACTIVE_ORG_KEY, org.id);
        set({ activeOrganization: org, activeOrganizationId: org.id });
      }
      return;
    }

    const token = get().accessToken;
    if (!token) return;

    try {
      const res = await fetch(`${BASE_URL}/auth/switch-org`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ organization_id: orgId }),
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        throw new Error(errBody.detail || 'Failed to switch organization');
      }
      localStorage.setItem(ACTIVE_ORG_KEY, orgId);
      const org = get().organizations.find((o) => o.id === orgId) || null;
      set({ activeOrganization: org, activeOrganizationId: orgId });
      await get().fetchUserContext();
    } catch (err) {
      console.error('Failed to switch organization:', err);
      throw err;
    }
  },

  hydrate: async () => {
    if (USE_MOCK) {
      try {
        const raw = localStorage.getItem(MOCK_STORAGE_KEY);
        if (raw) {
          const { user, token } = JSON.parse(raw) as { user: User; token: string };
          if (user && token) {
            set({ user, accessToken: token, isAuthenticated: true });
            await get().fetchUserContext();
          }
        }
      } catch {
        localStorage.removeItem(MOCK_STORAGE_KEY);
      }
      set({ hydrated: true });
      return;
    }

    try {
      const { data } = await getSupabase().auth.getSession();
      const session = data.session;
      if (session) {
        set({
          user: toUser(session.user),
          accessToken: session.access_token,
          isAuthenticated: true,
        });
        await get().fetchUserContext();
      }
    } catch {
      // ignore
    } finally {
      set({ hydrated: true });
    }
  },

  getToken: () => get().accessToken,

  setAccessToken: (token) => set({ accessToken: token }),
}));

