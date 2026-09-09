import { useEffect, useRef, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { Building2, Check, ChevronDown, LogOut, Radio, Shield, User } from 'lucide-react';
import { useAuthStore } from '../../store/authStore';
import { useUiStore } from '../../store/uiStore';
import { isMockMode } from '../../services/api';

const ROUTE_TITLES: [RegExp, string][] = [
  [/^\/dashboard/, 'Security Operations Center'],
  [/^\/phishing/, 'AI-Powered Phishing Detection'],
  [/^\/url-analysis/, 'Malicious URL & Website Detection'],
  [/^\/impersonation/, 'Digital Impersonation Detection'],
  [/^\/deepfake/, 'Deepfake & Manipulated Media Detection'],
  [/^\/account-takeover/, 'Credential Theft & Account Takeover'],
  [/^\/network-threats/, 'Network & API Threat Detection'],
  [/^\/alerts\/.+/, 'Alert Detail'],
  [/^\/alerts/, 'Security Alerts'],
  [/^\/incidents\/.+/, 'Incident Detail'],
  [/^\/incidents/, 'Incident Management'],
  [/^\/response-actions/, 'Response Actions'],
  [/^\/audit-logs/, 'Audit Logs'],
  [/^\/reports/, 'Reports & Export'],
  [/^\/settings/, 'Settings'],
];

export default function Topbar() {
  const location = useLocation();
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);
  const organizations = useAuthStore((s) => s.organizations);
  const activeOrganization = useAuthStore((s) => s.activeOrganization);
  const switchOrganization = useAuthStore((s) => s.switchOrganization);

  const liveSimulation = useUiStore((s) => s.liveSimulation);
  const toggleLiveSimulation = useUiStore((s) => s.toggleLiveSimulation);
  const addToast = useUiStore((s) => s.addToast);

  const [menuOpen, setMenuOpen] = useState(false);
  const [orgMenuOpen, setOrgMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const orgMenuRef = useRef<HTMLDivElement>(null);

  const title = ROUTE_TITLES.find(([re]) => re.test(location.pathname))?.[1] ?? 'CYBERGUARD';

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
      if (orgMenuRef.current && !orgMenuRef.current.contains(e.target as Node)) setOrgMenuOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const handleToggleSimulation = () => {
    toggleLiveSimulation();
    const next = !liveSimulation;
    addToast(next ? 'Live alerts enabled' : 'Live alerts disabled', next ? 'low' : 'safe');
  };

  const handleSelectOrg = async (orgId: string, orgName: string) => {
    try {
      setOrgMenuOpen(false);
      await switchOrganization(orgId);
      addToast(`Switched workspace to ${orgName}`, 'safe');
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to switch workspace', 'high');
    }
  };

  const currentOrg = activeOrganization || (organizations.length > 0 ? organizations[0] : null);

  return (
    <header className="flex h-14 items-center justify-between border-b border-slate-700/50 bg-slate-900/80 px-5 backdrop-blur">
      <h1 className="text-base font-semibold text-slate-100">{title}</h1>

      <div className="flex items-center gap-3">
        {/* Workspace / Organization Switcher */}
        <div className="relative" ref={orgMenuRef}>
          <button
            onClick={() => setOrgMenuOpen((o) => !o)}
            className="flex items-center gap-2 rounded-lg border border-slate-700/60 bg-slate-800/80 px-2.5 py-1.5 text-xs text-slate-200 transition hover:border-cyan-500/40 hover:bg-slate-800"
          >
            {currentOrg?.is_personal ? (
              <User className="h-3.5 w-3.5 text-cyan-400" />
            ) : (
              <Building2 className="h-3.5 w-3.5 text-purple-400" />
            )}
            <span className="max-w-[130px] truncate font-medium">
              {currentOrg?.name ?? 'Personal Workspace'}
            </span>
            <span className="rounded bg-slate-900/90 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider text-cyan-400">
              {currentOrg?.role ?? user?.role ?? 'admin'}
            </span>
            <ChevronDown className="h-3 w-3 text-slate-500" />
          </button>

          {orgMenuOpen && (
            <div className="absolute left-0 top-full z-30 mt-1 w-64 rounded-xl border border-slate-700/70 bg-slate-900 p-2 shadow-2xl backdrop-blur">
              <div className="px-2 py-1.5 font-mono text-[10px] uppercase tracking-wider text-slate-400">
                Workspaces & Teams
              </div>

              <div className="space-y-1">
                {organizations.length > 0 ? (
                  organizations.map((org) => {
                    const isSelected = (currentOrg?.id ?? '') === org.id;
                    return (
                      <button
                        key={org.id}
                        onClick={() => handleSelectOrg(org.id, org.name)}
                        className={`flex w-full items-center justify-between rounded-lg px-2.5 py-2 text-left text-xs transition ${
                          isSelected
                            ? 'bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30'
                            : 'text-slate-300 hover:bg-slate-800'
                        }`}
                      >
                        <div className="flex items-center gap-2 truncate">
                          {org.is_personal ? (
                            <User className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
                          ) : (
                            <Building2 className="h-3.5 w-3.5 text-purple-400 shrink-0" />
                          )}
                          <div className="truncate">
                            <div className="truncate font-medium">{org.name}</div>
                            <div className="font-mono text-[10px] text-slate-500">
                              {org.is_personal ? 'Single User' : 'Team SOC'} • {org.role}
                            </div>
                          </div>
                        </div>
                        {isSelected && <Check className="h-3.5 w-3.5 text-cyan-400 shrink-0 ml-2" />}
                      </button>
                    );
                  })
                ) : (
                  <div className="px-2 py-2 font-mono text-xs text-slate-500">No organizations found</div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* MOCK MODE badge if in mock mode */}
        {isMockMode() ? (
          <span className="rounded-md bg-cyan-500/15 px-2.5 py-1 font-mono text-[11px] font-bold tracking-wider text-cyan-400 ring-1 ring-cyan-500/50">
            MOCK MODE
          </span>
        ) : (
          <span className="rounded-md bg-emerald-500/15 px-2.5 py-1 font-mono text-[11px] font-bold tracking-wider text-emerald-400 ring-1 ring-emerald-500/50">
            CLOUD SOC
          </span>
        )}

        {/* Live alerts toggle */}
        <button
          onClick={handleToggleSimulation}
          className={`flex items-center gap-2 rounded-md px-2.5 py-1.5 text-xs font-medium ring-1 transition ${
            liveSimulation
              ? 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/50'
              : 'bg-slate-800/60 text-slate-400 ring-slate-700/50 hover:text-slate-200'
          }`}
        >
          {liveSimulation && <Radio className="h-3.5 w-3.5 animate-pulse text-emerald-400" />}
          <span>Live Alerts</span>
        </button>

        {/* User menu */}
        <div className="relative" ref={menuRef}>
          <button
            onClick={() => setMenuOpen((o) => !o)}
            className="flex items-center gap-2 rounded-md bg-slate-800/60 px-2.5 py-1.5 text-xs text-slate-300 ring-1 ring-slate-700/50 hover:bg-slate-800"
          >
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-cyan-500/20 text-cyan-300 ring-1 ring-cyan-500/40">
              <Shield className="h-3.5 w-3.5" />
            </span>
            <span className="hidden md:inline">{user?.name ?? 'Operator'}</span>
            <ChevronDown className="h-3.5 w-3.5 text-slate-500" />
          </button>
          {menuOpen && (
            <div className="absolute right-0 top-full z-30 mt-1 w-56 rounded-lg border border-slate-700/60 bg-slate-900 p-1.5 shadow-xl">
              <div className="px-2.5 py-2">
                <div className="flex items-center gap-2 text-sm text-slate-100">
                  <User className="h-3.5 w-3.5 text-slate-500" />
                  {user?.name}
                </div>
                <div className="mt-0.5 truncate pl-5.5 font-mono text-[11px] text-slate-500">{user?.email}</div>
                <div className="mt-1 pl-5.5 text-[10px] uppercase tracking-wider text-cyan-400">
                  Role: {currentOrg?.role ?? user?.role}
                </div>
              </div>
              <div className="my-1 border-t border-slate-700/50" />
              <button
                onClick={() => {
                  setMenuOpen(false);
                  logout();
                }}
                className="flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-sm text-slate-300 hover:bg-slate-800 hover:text-red-400"
              >
                <LogOut className="h-3.5 w-3.5" />
                Logout
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
