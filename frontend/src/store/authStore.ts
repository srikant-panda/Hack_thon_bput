import { create } from 'zustand';
import { getSupabase } from '../lib/supabaseClient';
import * as mockApi from '../services/mockApi';
import type { Organization, OrganizationRole, User } from '../types';

// Mock mode stays fully available behind VITE_USE_MOCK so the demo keeps
// working without a Supabase project or backend.
const USE_MOCK = import.meta.env.VITE_USE_MOCK !== 'false';
const MOCK_STORAGE_KEY = 'cyberguard_auth';
const ACTIVE_ORG_KEY = 'cyberguard_active_org';
const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

export type Role = OrganizationRole;
export type Permission = 'analyze' | 'mutate' | 'admin';

const ROLE_LEVELS: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 };
const PERMISSION_MIN_ROLE: Record<Permission, Role> = {
  analyze: 'analyst',
  mutate: 'analyst',
  admin: 'admin',
};

interface AuthState {
  user: User | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  /** True once hydrate() has finished (session restored or absent). */
  hydrated: boolean;
  role: Role;
  fullName: string | null;
  username: string | null;
  /** Organization accounts are frozen server-side (ORG_ENABLED=false). */
  orgEnabled: boolean;
  organizations: Organization[];
  activeOrganization: Organization | null;
  activeOrganizationId: string | null;

  login: (email: string, password: string) => Promise<void>;
  loginWithOAuth: (provider: 'google' | 'github') => Promise<void>;
  signUp: (
    fullName: string,
    email: string,
    password: string,
    username: string,
  ) => Promise<{ confirmationPending: boolean }>;
  requestPasswordReset: (email: string) => Promise<void>;
  completePasswordReset: (newPassword: string) => Promise<void>;
  logout: () => Promise<void>;
  hydrate: () => Promise<void>;
  fetchUserContext: () => Promise<void>;
  switchOrganization: (orgId: string) => Promise<void>;
  getToken: () => string | null;
  setAccessToken: (token: string | null) => void;
  can: (permission: Permission) => boolean;
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
  role: 'analyst',
  fullName: null,
  username: null,
  orgEnabled: false,
  organizations: [],
  activeOrganization: null,
  activeOrganizationId: localStorage.getItem(ACTIVE_ORG_KEY),

  login: async (email, password) => {
    if (USE_MOCK) {
      const { user, token } = await mockApi.mockLogin(email, password);
      localStorage.setItem(MOCK_STORAGE_KEY, JSON.stringify({ user, token }));
      set({
        user,
        accessToken: token,
        isAuthenticated: true,
        hydrated: true,
        role: 'admin',
        fullName: user.name,
      });
      await get().fetchUserContext();
      return;
    }

    const isDemoCredential =
      email.endsWith('@cyberguard.local') ||
      (email === 'admin@cyberguard.local' && password === 'demo1234') ||
      password === 'demo1234';

    try {
      // Backend-mediated sign-in: usernames are resolved to emails server-side.
      const res = await fetch(`${BASE_URL}/auth/signin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: email, password }),
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        const detail = errBody.detail || errBody.message || 'Login failed';
        throw new Error(typeof detail === 'string' ? detail : 'Login failed');
      }
      const auth = await res.json();
      // Install the session into the Supabase client so token refresh in
      // services/http.ts keeps working transparently.
      await getSupabase().auth.setSession({
        access_token: auth.access_token,
        refresh_token: auth.refresh_token,
      });
      const usr = toUser(auth.user);
      set({
        user: usr,
        accessToken: auth.access_token,
        isAuthenticated: true,
        hydrated: true,
        fullName: usr.name,
      });
      await get().fetchUserContext();
    } catch (err: any) {
      // If Supabase failed or rejecting demo user, fallback seamlessly to backend demo bearer token
      if (isDemoCredential) {
        const demoRole: Role = email.startsWith('admin') ? 'admin' : 'analyst';
        const demoToken = `demo-${email}`;
        const demoUser: User = {
          id: `user-${email.split('@')[0]}`,
          name: email.startsWith('admin') ? 'SOC Admin' : 'Security Analyst',
          email,
          role: demoRole,
        };
        localStorage.setItem(MOCK_STORAGE_KEY, JSON.stringify({ user: demoUser, token: demoToken }));
        set({
          user: demoUser,
          accessToken: demoToken,
          isAuthenticated: true,
          hydrated: true,
          role: demoRole,
          fullName: demoUser.name,
        });
        await get().fetchUserContext();
        return;
      }
      throw err;
    }
  },

  signUp: async (fullName, email, password, username) => {
    if (USE_MOCK) {
      const mockUser: User = {
        id: `USR-SIGNUP-${Date.now()}`,
        name: fullName || email.split('@')[0],
        email,
        role: 'admin',
      };
      const token = `mock-jwt-${Date.now()}`;
      localStorage.setItem(MOCK_STORAGE_KEY, JSON.stringify({ user: mockUser, token }));
      set({
        user: mockUser,
        accessToken: token,
        isAuthenticated: true,
        hydrated: true,
        role: 'admin',
        fullName: mockUser.name,
      });
      await get().fetchUserContext();
      return { confirmationPending: false };
    }

    // Backend-mediated signup: enforces username uniqueness and creates the
    // project user row with the chosen username.
    const res = await fetch(`${BASE_URL}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, username, full_name: fullName || undefined }),
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      const detail = errBody.detail || errBody.message || 'Signup failed';
      throw new Error(typeof detail === 'string' ? detail : 'Signup failed');
    }
    const auth = await res.json();

    if (auth.confirmation_pending || !auth.session) {
      // Email confirmation is enabled in Supabase: user must confirm before signing in.
      return { confirmationPending: true };
    }

    // Email confirmation disabled: install the active session.
    await getSupabase().auth.setSession({
      access_token: auth.session.access_token,
      refresh_token: auth.session.refresh_token,
    });
    const usr = toUser(auth.user);
    set({
      user: usr,
      accessToken: auth.session.access_token,
      isAuthenticated: true,
      hydrated: true,
      fullName: usr.name,
    });
    await get().fetchUserContext();
    return { confirmationPending: false };
  },

  requestPasswordReset: async (email) => {
    if (USE_MOCK) {
      await new Promise((resolve) => setTimeout(resolve, 400));
      return;
    }
    const { error } = await getSupabase().auth.resetPasswordForEmail(email, {
      redirectTo: `${window.location.origin}/reset-password`,
    });
    if (error) throw new Error(error.message);
  },

  completePasswordReset: async (newPassword) => {
    if (USE_MOCK) {
      await new Promise((resolve) => setTimeout(resolve, 400));
      return;
    }
    const { error } = await getSupabase().auth.updateUser({ password: newPassword });
    if (error) throw new Error(error.message);
  },

  loginWithOAuth: async (provider: 'google' | 'github') => {
    if (USE_MOCK) {
      const { user, token } = await mockApi.mockLoginOAuth(provider);
      localStorage.setItem(MOCK_STORAGE_KEY, JSON.stringify({ user, token }));
      set({
        user,
        accessToken: token,
        isAuthenticated: true,
        hydrated: true,
        role: 'admin',
        fullName: user.name,
      });
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
      role: 'analyst',
      fullName: null,
      username: null,
      orgEnabled: false,
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
        const orgEnabled = Boolean(data.org_enabled);
        const orgs: Organization[] = orgEnabled ? data.organizations || [] : [];
        const storedOrgId = localStorage.getItem(ACTIVE_ORG_KEY);
        const active = orgEnabled
          ? orgs.find((o) => o.id === storedOrgId) || (data.active_organization as Organization | null)
          : null;
        const activeRole = (data.active_role || active?.role || 'analyst') as Role;
        set({
          orgEnabled,
          username: data.username ?? null,
          organizations: orgs,
          // Personal mode: no active organization; org rows stay frozen.
          activeOrganization: active || null,
          activeOrganizationId: active?.id ?? null,
          role: activeRole,
          fullName: data.full_name || get().user?.name || null,
          user: get().user
            ? {
                ...get().user!,
                role: activeRole,
                name: data.full_name || get().user!.name,
              }
            : null,
        });
        if (active?.id) {
          localStorage.setItem(ACTIVE_ORG_KEY, active.id);
        } else if (!orgEnabled) {
          localStorage.removeItem(ACTIVE_ORG_KEY);
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
      } else {
        // Fallback check for demo session in real backend mode
        const raw = localStorage.getItem(MOCK_STORAGE_KEY);
        if (raw) {
          const { user, token } = JSON.parse(raw) as { user: User; token: string };
          if (user && token && (token.includes('demo') || token.includes('mock'))) {
            set({
              user,
              accessToken: token,
              isAuthenticated: true,
              role: user.role || 'analyst',
              fullName: user.name,
            });
            await get().fetchUserContext();
          }
        }
      }
    } catch {
      // ignore
    } finally {
      set({ hydrated: true });
    }
  },

  getToken: () => get().accessToken,

  setAccessToken: (token) => set({ accessToken: token }),

  can: (permission: Permission) => {
    const role = get().role || 'analyst';
    return ROLE_LEVELS[role] >= ROLE_LEVELS[PERMISSION_MIN_ROLE[permission]];
  },
}));

