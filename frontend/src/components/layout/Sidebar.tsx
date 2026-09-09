import { NavLink } from 'react-router-dom';
import {
  Bell,
  Bot,
  Building2,
  ChevronsLeft,
  ChevronsRight,
  FileBarChart,
  KeyRound,
  LayoutDashboard,
  Link,
  Mail,
  Network,
  ScrollText,
  Settings,
  Shield,
  ShieldAlert,
  UserX,
  Video,
  Zap,
} from 'lucide-react';
import { useUiStore } from '../../store/uiStore';

const NAV_ITEMS: { to: string; label: string; icon: typeof Bell }[] = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/phishing', label: 'Phishing Analysis', icon: Mail },
  { to: '/url-analysis', label: 'URL Analysis', icon: Link },
  { to: '/impersonation', label: 'Impersonation', icon: UserX },
  { to: '/deepfake', label: 'Deepfake Detection', icon: Video },
  { to: '/account-takeover', label: 'Account Takeover', icon: KeyRound },
  { to: '/network-threats', label: 'Network & API', icon: Network },
  { to: '/alerts', label: 'Alerts', icon: Bell },
  { to: '/incidents', label: 'Incidents', icon: ShieldAlert },
  { to: '/response-actions', label: 'Response Actions', icon: Zap },
  { to: '/organization', label: 'Organization & Team', icon: Building2 },
  { to: '/audit-logs', label: 'Audit Logs', icon: ScrollText },
  { to: '/reports', label: 'Reports', icon: FileBarChart },
  { to: '/settings', label: 'Settings', icon: Settings },
];

export default function Sidebar() {
  const collapsed = useUiStore((s) => s.sidebarCollapsed);
  const setAssistantOpen = useUiStore((s) => s.setAssistantOpen);

  return (
    <aside
      className={`flex h-full flex-col border-r border-zinc-800 bg-zinc-950 backdrop-blur transition-all duration-200 ${
        collapsed ? 'w-16' : 'w-64'
      }`}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 border-b border-zinc-800 px-4 py-4">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-red-500/10 ring-1 ring-red-500/40">
          <Shield className="h-5 w-5 text-red-400" />
        </div>
        {!collapsed && (
          <div className="min-w-0">
            <div className="truncate font-mono text-sm font-bold tracking-widest text-red-400">CYBERGUARD</div>
            <div className="truncate text-[10px] uppercase tracking-wider text-zinc-500">SOC Command Center</div>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3">
        {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            title={collapsed ? label : undefined}
            className={({ isActive }) =>
              `flex items-center gap-3 border-l-2 py-2 pr-3 text-sm transition ${
                collapsed ? 'justify-center pl-0' : 'pl-4'
              } ${
                isActive
                  ? 'border-red-600 bg-zinc-900 text-red-400 font-semibold'
                  : 'border-transparent text-zinc-400 hover:bg-zinc-900/50 hover:text-zinc-100'
              }`
            }
          >
            <Icon className="h-4 w-4 shrink-0" />
            {!collapsed && <span className="truncate">{label}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Bottom section */}
      <div className="border-t border-zinc-800 p-3 space-y-2">
        <button
          onClick={() => setAssistantOpen(true)}
          className={`flex w-full items-center gap-3 rounded-lg bg-red-500/10 px-3 py-2.5 text-sm font-medium text-red-400 ring-1 ring-red-500/30 hover:bg-red-500/20 transition ${
            collapsed ? 'justify-center' : ''
          }`}
        >
          <Bot className="h-4 w-4 shrink-0" />
          {!collapsed && <span>SOC Assistant</span>}
        </button>
        <button
          onClick={() => useUiStore.getState().toggleSidebar()}
          className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-xs text-zinc-500 hover:bg-zinc-900/60 hover:text-zinc-300 transition ${
            collapsed ? 'justify-center' : ''
          }`}
        >
          {collapsed ? <ChevronsRight className="h-4 w-4" /> : <ChevronsLeft className="h-4 w-4" />}
          {!collapsed && <span>Collapse Sidebar</span>}
        </button>
      </div>
    </aside>
  );
}
