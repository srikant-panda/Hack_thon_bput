import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  Eye,
  Globe,
  KeyRound,
  Lock,
  Network,
  Radio,
  Shield,
  Sparkles,
  Terminal,
  User,
  Users,
  Zap,
} from 'lucide-react';
import { useAuthStore } from '../store/authStore';

export default function LandingPage() {
  const navigate = useNavigate();
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const [activeTab, setActiveTab] = useState<'single' | 'org'>('single');

  const threatEngines = [
    {
      id: 'phishing',
      name: 'AI Phishing Detection',
      icon: MailIcon,
      badge: 'Email & Messaging',
      color: 'text-amber-400',
      border: 'border-amber-500/20 hover:border-amber-500/50',
      bg: 'bg-amber-500/5',
      desc: 'Deep lexical analysis, urgent tone detection, and spoofed header inspection cross-referenced with credential-harvesting indicators.',
    },
    {
      id: 'url',
      name: 'Malicious URL & Typosquatting',
      icon: Globe,
      badge: 'Web & Domains',
      color: 'text-cyan-400',
      border: 'border-cyan-500/20 hover:border-cyan-500/50',
      bg: 'bg-cyan-500/5',
      desc: 'Punycode homograph attacks, high-entropy subdomain generation, and nested redirect chain tracer with WHOIS heuristics.',
    },
    {
      id: 'impersonation',
      name: 'Digital Impersonation',
      icon: Users,
      badge: 'Identity Defense',
      color: 'text-rose-400',
      border: 'border-rose-500/20 hover:border-rose-500/50',
      bg: 'bg-rose-500/5',
      desc: 'Executive spoofing, cousin domain mapping, lookalike email handles, and unauthorized brand asset exploitation defenses.',
    },
    {
      id: 'deepfake',
      name: 'Deepfake & Media Forensics',
      icon: Eye,
      badge: 'Synthetics & Audio',
      color: 'text-purple-400',
      border: 'border-purple-500/20 hover:border-purple-500/50',
      bg: 'bg-purple-500/5',
      desc: 'Frequency-domain FFT artifact inspection, spectral face warps, biometric discontinuities, and synthetic voice detection.',
    },
    {
      id: 'account_takeover',
      name: 'Account Takeover (ATO)',
      icon: KeyRound,
      badge: 'Auth & Sessions',
      color: 'text-red-400',
      border: 'border-red-500/20 hover:border-red-500/50',
      bg: 'bg-red-500/5',
      desc: 'Impossible travel velocity algorithms, brute-force cluster detection, credential stuffing signatures, and anomalous session fingerprinting.',
    },
    {
      id: 'network',
      name: 'Network Threat Intelligence',
      icon: Network,
      badge: 'Traffic & API',
      color: 'text-emerald-400',
      border: 'border-emerald-500/20 hover:border-emerald-500/50',
      bg: 'bg-emerald-500/5',
      desc: 'API token replay traps, port scan heuristics, zero-day endpoint scanning, and asymmetric payload spike telemetry.',
    },
  ];

  const simulatedTelemetry = [
    {
      time: '12:41:04',
      type: 'PHISHING',
      source: 'hr-portal.support-internal.com',
      severity: 'HIGH',
      action: 'Domain Quarantined',
      mitre: 'T1566.002',
    },
    {
      time: '12:41:19',
      type: 'ATO DETECT',
      source: 'IP 185.220.101.5 (Tor Exit)',
      severity: 'CRITICAL',
      action: 'MFA Force Triggered',
      mitre: 'T1110.003',
    },
    {
      time: '12:41:35',
      type: 'DEEPFAKE',
      source: 'CFO_Voice_Memo_Q3.mp4',
      severity: 'HIGH',
      action: 'Flagged for Review',
      mitre: 'T1565.001',
    },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 selection:bg-cyan-500 selection:text-slate-950 font-sans">
      {/* Background glow effects */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden">
        <div className="absolute -top-40 left-1/2 -translate-x-1/2 w-[700px] h-[500px] bg-cyan-500/10 blur-[140px] rounded-full" />
        <div className="absolute top-[45%] -left-32 w-[500px] h-[400px] bg-emerald-500/5 blur-[120px] rounded-full" />
        <div className="absolute top-[60%] -right-32 w-[500px] h-[400px] bg-purple-500/5 blur-[120px] rounded-full" />
      </div>

      {/* Navigation Header */}
      <header className="sticky top-0 z-50 border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 ring-1 ring-cyan-500/40 shadow-md shadow-cyan-500/10">
              <Shield className="h-5 w-5 text-cyan-400" />
            </div>
            <div>
              <span className="font-mono text-lg font-bold tracking-widest text-cyan-400">CYBERGUARD</span>
              <span className="hidden sm:inline-block ml-2 rounded-full bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-400">
                SOC 2.0
              </span>
            </div>
          </div>

          <nav className="hidden md:flex items-center gap-8 font-mono text-xs text-slate-400">
            <a href="#engines" className="hover:text-cyan-400 transition">
              Detection Engines
            </a>
            <a href="#architecture" className="hover:text-cyan-400 transition">
              Dual Architecture
            </a>
            <a href="#telemetry" className="hover:text-cyan-400 transition">
              Live Telemetry
            </a>
            <a href="#pipeline" className="hover:text-cyan-400 transition">
              AI Pipeline
            </a>
          </nav>

          <div className="flex items-center gap-3">
            {isAuthenticated ? (
              <button
                onClick={() => navigate('/dashboard')}
                className="flex items-center gap-2 rounded-lg bg-cyan-500 px-4 py-2 text-xs font-bold text-slate-950 transition hover:bg-cyan-400 shadow-md shadow-cyan-500/20"
              >
                <span>SOC Console</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            ) : (
              <>
                <Link
                  to="/login"
                  className="rounded-lg px-3.5 py-1.5 font-mono text-xs text-slate-300 transition hover:text-cyan-400"
                >
                  Sign In
                </Link>
                <Link
                  to="/login"
                  className="flex items-center gap-2 rounded-lg bg-cyan-500 px-4 py-2 text-xs font-bold text-slate-950 transition hover:bg-cyan-400 shadow-md shadow-cyan-500/20"
                >
                  <span>Launch Platform</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              </>
            )}
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative pt-20 pb-24 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <div className="text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3.5 py-1 text-xs text-cyan-300 shadow-sm backdrop-blur mb-6">
            <Radio className="h-3.5 w-3.5 animate-pulse text-cyan-400" />
            <span className="font-mono font-medium">NEXT-GEN AI SECURITY OPERATIONS • DUAL WORKSPACE READY</span>
          </div>

          <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-slate-100 leading-tight">
            Autonomous Threat Defense,{' '}
            <span className="bg-gradient-to-r from-cyan-400 via-teal-300 to-emerald-400 bg-clip-text text-transparent">
              Phishing Elimination
            </span>{' '}
            & Deepfake Forensics
          </h1>

          <p className="mt-6 text-base sm:text-lg text-slate-400 leading-relaxed">
            Enterprise-grade SecOps combining ultra-fast deterministic heuristic engines with adaptive LLM threat
            analysis. Switch effortlessly between an autonomous <strong>Single-User Workspace</strong> and a collaborative{' '}
            <strong>Team Organization</strong> with full role-based access control.
          </p>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-4">
            <button
              onClick={() => navigate(isAuthenticated ? '/dashboard' : '/login')}
              className="flex items-center gap-2 rounded-xl bg-cyan-500 px-6 py-3.5 text-sm font-bold text-slate-950 shadow-lg shadow-cyan-500/25 transition hover:bg-cyan-400 hover:scale-[1.02]"
            >
              <Zap className="h-4 w-4" />
              <span>{isAuthenticated ? 'Open Security Operations Center' : 'Access CyberGuard Free'}</span>
            </button>
            <a
              href="#engines"
              className="flex items-center gap-2 rounded-xl border border-slate-700/80 bg-slate-900/60 px-5 py-3.5 text-sm font-semibold text-slate-300 transition hover:border-slate-600 hover:bg-slate-800"
            >
              <Terminal className="h-4 w-4 text-cyan-400" />
              <span>Explore 6 Detection Engines</span>
            </a>
          </div>

          {/* Quick Stats Banner */}
          <div className="mt-14 grid grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl mx-auto">
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 backdrop-blur">
              <div className="font-mono text-2xl font-bold text-cyan-400">&lt; 15ms</div>
              <div className="mt-1 text-xs text-slate-400 font-mono">Deterministic Heuristics</div>
            </div>
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 backdrop-blur">
              <div className="font-mono text-2xl font-bold text-emerald-400">100% Async</div>
              <div className="mt-1 text-xs text-slate-400 font-mono">SQLAlchemy Engine</div>
            </div>
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 backdrop-blur">
              <div className="font-mono text-2xl font-bold text-purple-400">Dual-Mode</div>
              <div className="mt-1 text-xs text-slate-400 font-mono">Single-User & Org RBAC</div>
            </div>
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 backdrop-blur">
              <div className="font-mono text-2xl font-bold text-amber-400">MITRE ATT&CK</div>
              <div className="mt-1 text-xs text-slate-400 font-mono">Automated TTP Mapping</div>
            </div>
          </div>
        </div>
      </section>

      {/* Interactive Live SOC Telemetry Simulator Preview */}
      <section id="telemetry" className="relative py-12 px-4 sm:px-6 lg:px-8 max-w-6xl mx-auto">
        <div className="rounded-2xl border border-slate-800/90 bg-slate-900/80 shadow-2xl backdrop-blur overflow-hidden">
          {/* Header Bar */}
          <div className="flex items-center justify-between border-b border-slate-800 px-5 py-3.5 bg-slate-950/60">
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-red-500/80" />
              <span className="h-3 w-3 rounded-full bg-yellow-500/80" />
              <span className="h-3 w-3 rounded-full bg-emerald-500/80" />
              <span className="ml-3 font-mono text-xs text-slate-400">cyberguard-soc-sensor-cluster-01 [LIVE]</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1.5 font-mono text-[11px] text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                <Activity className="h-3 w-3 animate-pulse" />
                ACTIVE DEFENSE
              </span>
            </div>
          </div>

          {/* Terminal Body */}
          <div className="p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-mono text-xs uppercase tracking-wider text-slate-400">
                Incoming Event Stream & MITRE Automated Triage
              </h3>
              <span className="font-mono text-[11px] text-cyan-400">Auto-Remediate: ON</span>
            </div>

            <div className="space-y-3 font-mono text-xs">
              {simulatedTelemetry.map((item, idx) => (
                <div
                  key={idx}
                  className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-950/60 p-3 hover:border-slate-700 transition"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-slate-500">{item.time}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        item.severity === 'CRITICAL'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                          : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                      }`}
                    >
                      {item.type}
                    </span>
                    <span className="text-slate-300 font-mono truncate max-w-xs sm:max-w-md">{item.source}</span>
                  </div>
                  <div className="flex items-center gap-3 self-end sm:self-auto">
                    <span className="rounded bg-slate-800 px-2 py-0.5 text-[11px] text-cyan-300 font-mono">
                      {item.mitre}
                    </span>
                    <span className="flex items-center gap-1 text-[11px] text-emerald-400">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      {item.action}
                    </span>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-6 flex flex-wrap items-center justify-between border-t border-slate-800/80 pt-4 text-xs text-slate-400">
              <span>Sensor Feed: 6 Threat Modules Active</span>
              <button
                onClick={() => navigate('/dashboard')}
                className="flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300 transition font-mono"
              >
                <span>Launch Interactive SOC Simulator</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* 6 Specialized Threat Engines */}
      <section id="engines" className="relative py-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <div className="text-center max-w-2xl mx-auto mb-16">
          <h2 className="font-mono text-xs uppercase tracking-widest text-cyan-400 font-semibold">
            COMPREHENSIVE THREAT TAXONOMY
          </h2>
          <p className="mt-3 text-3xl font-bold tracking-tight text-slate-100 sm:text-4xl">
            6 Specialized AI Detection Engines
          </p>
          <p className="mt-4 text-sm text-slate-400">
            From modern phishing campaigns and weaponized typosquatting to deepfake voice cloning and API abuse.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {threatEngines.map((engine) => {
            const Icon = engine.icon;
            return (
              <div
                key={engine.id}
                className={`group relative rounded-2xl border ${engine.border} bg-slate-900/60 p-6 backdrop-blur transition-all duration-200 hover:-translate-y-1 hover:shadow-xl`}
              >
                <div className="flex items-center justify-between mb-4">
                  <div className={`flex h-11 w-11 items-center justify-center rounded-xl ${engine.bg} ${engine.color}`}>
                    <Icon className="h-5 w-5" />
                  </div>
                  <span className="rounded-full border border-slate-700/80 bg-slate-800/80 px-2.5 py-0.5 font-mono text-[10px] text-slate-300">
                    {engine.badge}
                  </span>
                </div>

                <h3 className="text-base font-semibold text-slate-100 group-hover:text-cyan-300 transition">
                  {engine.name}
                </h3>
                <p className="mt-2 text-xs text-slate-400 leading-relaxed">{engine.desc}</p>

                <div className="mt-6 flex items-center gap-2 border-t border-slate-800/60 pt-4">
                  <Link
                    to={isAuthenticated ? `/${engine.id.replace('_', '-')}` : '/login'}
                    className="flex items-center gap-1.5 font-mono text-xs text-cyan-400 hover:text-cyan-300 transition"
                  >
                    <span>Analyze live samples</span>
                    <ArrowRight className="h-3 w-3" />
                  </Link>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Dual Architecture: Single-User vs Multi-Tenant Organization */}
      <section id="architecture" className="relative py-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <div className="text-center max-w-2xl mx-auto mb-12">
          <h2 className="font-mono text-xs uppercase tracking-widest text-cyan-400 font-semibold">
            ADAPTIVE MULTI-TENANCY
          </h2>
          <p className="mt-3 text-3xl font-bold tracking-tight text-slate-100 sm:text-4xl">
            Built for Solo Operators & Enterprise SOC Teams
          </p>
          <p className="mt-4 text-sm text-slate-400">
            One platform. Seamless transition between private research sandbox and collaborative security team.
          </p>
        </div>

        {/* Tab Selector */}
        <div className="flex justify-center mb-10">
          <div className="inline-flex rounded-xl border border-slate-800 bg-slate-900/90 p-1">
            <button
              onClick={() => setActiveTab('single')}
              className={`flex items-center gap-2 rounded-lg px-4 py-2 font-mono text-xs font-semibold transition ${
                activeTab === 'single'
                  ? 'bg-cyan-500 text-slate-950 shadow'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <User className="h-4 w-4" />
              <span>Single-User Mode (Personal Workspace)</span>
            </button>
            <button
              onClick={() => setActiveTab('org')}
              className={`flex items-center gap-2 rounded-lg px-4 py-2 font-mono text-xs font-semibold transition ${
                activeTab === 'org'
                  ? 'bg-cyan-500 text-slate-950 shadow'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Users className="h-4 w-4" />
              <span>Organization Mode (Enterprise SOC)</span>
            </button>
          </div>
        </div>

        {/* Architecture Content */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-8 backdrop-blur max-w-4xl mx-auto">
          {activeTab === 'single' ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
              <div>
                <div className="inline-flex items-center gap-2 rounded bg-cyan-500/10 px-2.5 py-1 text-xs font-mono text-cyan-400 mb-3 border border-cyan-500/20">
                  <User className="h-3.5 w-3.5" />
                  <span>AUTONOMOUS SECURITY RESEARCHER</span>
                </div>
                <h3 className="text-2xl font-bold text-slate-100">Private Personal Workspace</h3>
                <p className="mt-3 text-sm text-slate-400 leading-relaxed">
                  Every user is instantly provisioned with a private, fully isolated personal workspace upon login.
                  Enjoy unrestricted admin control without complex role management or permissions.
                </p>
                <ul className="mt-5 space-y-2.5 font-mono text-xs text-slate-300">
                  <li className="flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    <span>Instant provisioning with zero manual setup</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    <span>Isolated event logs, alerts, and custom SOAR playbooks</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    <span>Full autonomous control (automatic admin privilege)</span>
                  </li>
                </ul>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-5 font-mono text-xs">
                <div className="text-slate-500 mb-3">// HTTP Request Header Scoping</div>
                <div className="text-cyan-400">GET /api/v1/alerts</div>
                <div className="text-slate-400">Authorization: Bearer &lt;token&gt;</div>
                <div className="text-slate-400">X-Organization-Id: personal-workspace-001</div>
                <div className="mt-4 pt-3 border-t border-slate-800 text-slate-400">
                  <span className="text-emerald-400">&gt; Tenant Context:</span> Single User [Owner]
                  <br />
                  <span className="text-emerald-400">&gt; Enforcement:</span> Scoped exclusively to user data
                </div>
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
              <div>
                <div className="inline-flex items-center gap-2 rounded bg-purple-500/10 px-2.5 py-1 text-xs font-mono text-purple-400 mb-3 border border-purple-500/20">
                  <Users className="h-3.5 w-3.5" />
                  <span>ENTERPRISE TEAM COLLABORATION</span>
                </div>
                <h3 className="text-2xl font-bold text-slate-100">Multi-Operator SOC with RBAC</h3>
                <p className="mt-3 text-sm text-slate-400 leading-relaxed">
                  Join or manage multi-operator security operations centers with strictly enforced Role-Based Access
                  Control (RBAC). Coordinate triage, assign incidents, and preserve forensic audit compliance.
                </p>
                <div className="mt-5 space-y-2 text-xs">
                  <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
                    <span className="font-mono font-bold text-red-400">Admin</span>
                    <span className="text-slate-400">Catalog configs, user invites, organization settings</span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
                    <span className="font-mono font-bold text-cyan-400">Analyst</span>
                    <span className="text-slate-400">Investigate alerts, trigger actions, update incidents</span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
                    <span className="font-mono font-bold text-slate-400">Viewer</span>
                    <span className="text-slate-400">Read-only dashboard, audit log inspection, metrics</span>
                  </div>
                </div>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-5 font-mono text-xs">
                <div className="text-slate-500 mb-3">// Team SOC Context Switching</div>
                <div className="text-cyan-400">POST /api/v1/auth/switch-org</div>
                <div className="text-slate-400">Body: {`{ "organization_id": "soc-alpha" }`}</div>
                <div className="mt-4 pt-3 border-t border-slate-800 text-slate-400">
                  <span className="text-emerald-400">&gt; Active Org:</span> Global Security Operations
                  <br />
                  <span className="text-emerald-400">&gt; Assigned Role:</span> Senior SOC Analyst
                  <br />
                  <span className="text-emerald-400">&gt; Audit Trail:</span> Cryptographically tied to Org ID
                </div>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* AI Pipeline Architecture */}
      <section id="pipeline" className="relative py-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <div className="text-center max-w-2xl mx-auto mb-16">
          <h2 className="font-mono text-xs uppercase tracking-widest text-cyan-400 font-semibold">
            DETECTION PIPELINE
          </h2>
          <p className="mt-3 text-3xl font-bold tracking-tight text-slate-100 sm:text-4xl">
            Hybrid Deterministic + LLM Intelligence
          </p>
          <p className="mt-4 text-sm text-slate-400">
            Sub-millisecond heuristics catch obvious threats instantly; OpenRouter neural models formulate deep threat
            explanations and MITRE ATT&CK recommendations.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400 mb-3">
              <Terminal className="h-5 w-5" />
            </div>
            <h4 className="font-mono text-sm font-semibold text-slate-100">1. Ingestion</h4>
            <p className="mt-2 text-xs text-slate-400">
              Raw events stream into FastAPI via asynchronous endpoints, with payload normalization and metadata parsing.
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-amber-500/10 text-amber-400 mb-3">
              <Zap className="h-5 w-5" />
            </div>
            <h4 className="font-mono text-sm font-semibold text-slate-100">2. Heuristics</h4>
            <p className="mt-2 text-xs text-slate-400">
              Deterministic rule engines score lexical features, entropy, punycode, and geo-travel anomalies in &lt;15ms.
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-purple-500/10 text-purple-400 mb-3">
              <Sparkles className="h-5 w-5" />
            </div>
            <h4 className="font-mono text-sm font-semibold text-slate-100">3. Neural Reasoning</h4>
            <p className="mt-2 text-xs text-slate-400">
              High-risk events trigger OpenRouter LLMs with cascading fallbacks to synthesize attack explanations and
              MITRE tags.
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400 mb-3">
              <Lock className="h-5 w-5" />
            </div>
            <h4 className="font-mono text-sm font-semibold text-slate-100">4. SOAR Response</h4>
            <p className="mt-2 text-xs text-slate-400">
              Action catalog executes automated IP blocks, credential resets, or routes for human analyst approval.
            </p>
          </div>
        </div>
      </section>

      {/* CTA Banner */}
      <section className="relative py-16 px-4 sm:px-6 lg:px-8 max-w-5xl mx-auto">
        <div className="rounded-3xl border border-cyan-500/30 bg-gradient-to-b from-cyan-950/40 to-slate-900/90 p-8 sm:p-12 text-center shadow-2xl backdrop-blur relative overflow-hidden">
          <div className="absolute top-0 right-0 -mt-10 -mr-10 h-48 w-48 rounded-full bg-cyan-500/10 blur-2xl pointer-events-none" />
          <h2 className="text-3xl sm:text-4xl font-extrabold text-slate-100">
            Ready to Protect Your Infrastructure?
          </h2>
          <p className="mt-4 max-w-xl mx-auto text-sm sm:text-base text-slate-300">
            Experience complete cyber threat detection with real-time AI reasoning, multi-tenant collaboration, and
            automated defense playbooks.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-4">
            <button
              onClick={() => navigate(isAuthenticated ? '/dashboard' : '/login')}
              className="flex items-center gap-2 rounded-xl bg-cyan-500 px-6 py-3.5 text-sm font-bold text-slate-950 shadow-lg shadow-cyan-500/30 transition hover:bg-cyan-400"
            >
              <span>Launch CyberGuard Console</span>
              <ArrowRight className="h-4 w-4" />
            </button>
            <Link
              to="/login"
              className="rounded-xl border border-slate-700 bg-slate-800/80 px-6 py-3.5 text-sm font-semibold text-slate-200 transition hover:bg-slate-700"
            >
              OAuth Sign In
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 py-10 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 font-mono text-xs text-slate-500">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-cyan-400" />
            <span className="text-slate-300 font-bold tracking-wider">CYBERGUARD PLATFORM</span>
            <span>• FastAPI + SQLAlchemy + Supabase Auth</span>
          </div>
          <div className="flex items-center gap-6">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              All Systems Operational
            </span>
            <Link to="/dashboard" className="text-slate-400 hover:text-cyan-400 transition">
              Dashboard
            </Link>
            <Link to="/login" className="text-slate-400 hover:text-cyan-400 transition">
              Login
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}

function MailIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      {...props}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      viewBox="0 0 24 24"
    >
      <rect width="20" height="16" x="2" y="4" rx="2" />
      <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
    </svg>
  );
}
