import type {
  Alert,
  AnalysisResult,
  AuditLog,
  DashboardSummary,
  Incident,
  IncidentStatus,
  ResponseActionCatalog,
  ResponseExecution,
  Severity,
  ThreatModule,
  User,
  Organization,
  UserContext,
} from '../types';
import {
  analyzeApiLog,
  analyzeAuthLog,
  analyzeEmailText,
  analyzeImpersonation,
  analyzeMedia,
  analyzeNetworkFlow,
  analyzeUrl,
  getSeverityFromScore,
  type ApiLogInput,
  type AuthEventInput,
  type FlowInput,
} from './mockEngine';
import { addAuditLog, db } from './mockData';

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const jitter = () => delay(400 + Math.floor(Math.random() * 500));

const DEMO_USER: User = {
  id: 'USR-001',
  name: 'SOC Administrator',
  email: 'admin@cyberguard.local',
  role: 'admin',
};

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
export async function mockLogin(email: string, password: string): Promise<{ user: User; token: string }> {
  await jitter();
  if (email.trim().toLowerCase() === 'admin@cyberguard.local' && password === 'demo1234') {
    addAuditLog({
      userId: DEMO_USER.id,
      userName: DEMO_USER.email,
      action: 'LOGIN',
      resource: 'auth/session',
      details: 'Successful mock login',
    });
    return { user: DEMO_USER, token: `mock-jwt-${Date.now()}` };
  }
  throw new Error('Invalid credentials. Use admin@cyberguard.local / demo1234');
}

const MOCK_ORGS: Organization[] = [
  {
    id: 'org-personal-001',
    name: 'Personal Workspace',
    slug: 'personal-workspace',
    is_personal: true,
    role: 'admin',
  },
  {
    id: 'org-corp-001',
    name: 'Enterprise SOC Operations',
    slug: 'enterprise-soc-operations',
    is_personal: false,
    role: 'admin',
  },
];

export async function mockLoginOAuth(provider: 'google' | 'github'): Promise<{ user: User; token: string }> {
  await jitter();
  const oauthUser: User = {
    id: `USR-${provider.toUpperCase()}-001`,
    name: provider === 'google' ? 'Google SOC Specialist' : 'GitHub Security Engineer',
    email: provider === 'google' ? 'analyst@gmail.com' : 'devsecops@github.com',
    role: 'admin',
  };
  addAuditLog({
    userId: oauthUser.id,
    userName: oauthUser.email,
    action: 'OAUTH_LOGIN',
    resource: `auth/${provider}`,
    details: `Successful OAuth login with ${provider}`,
  });
  return { user: oauthUser, token: `mock-oauth-${provider}-${Date.now()}` };
}

export async function mockGetUserContext(): Promise<UserContext> {
  await jitter();
  return {
    id: DEMO_USER.id,
    email: DEMO_USER.email,
    full_name: DEMO_USER.name,
    is_single_user: false,
    active_role: 'admin',
    active_organization: {
      id: MOCK_ORGS[0].id,
      name: MOCK_ORGS[0].name,
      is_personal: MOCK_ORGS[0].is_personal,
      role: MOCK_ORGS[0].role,
    },
    personal_organization_id: MOCK_ORGS[0].id,
    organizations: [...MOCK_ORGS],
  };
}

export async function mockListOrganizations(): Promise<Organization[]> {
  await jitter();
  return [...MOCK_ORGS];
}

export async function mockCreateOrganization(name: string): Promise<Organization> {
  await jitter();
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  const newOrg: Organization = {
    id: `org-${Date.now()}`,
    name,
    slug,
    is_personal: false,
    role: 'admin',
  };
  MOCK_ORGS.push(newOrg);
  return newOrg;
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------
export async function mockGetDashboardSummary(): Promise<DashboardSummary> {
  await jitter();
  const alerts = db.alerts;
  const countBy = (fn: (a: Alert) => boolean) => alerts.filter(fn).length;

  const bands: { name: string; color: string }[] = [
    { name: 'Safe', color: '#10b981' },
    { name: 'Low', color: '#eab308' },
    { name: 'Medium', color: '#f59e0b' },
    { name: 'High', color: '#f97316' },
    { name: 'Critical', color: '#ef4444' },
  ];
  const riskDistribution = bands.map((b) => ({
    name: b.name,
    color: b.color,
    value: countBy((a) => a.severity === b.name.toLowerCase() as Severity),
  }));

  const moduleLabels: [ThreatModule, string][] = [
    ['phishing', 'Phishing'],
    ['url', 'Malicious URL'],
    ['impersonation', 'Impersonation'],
    ['deepfake', 'Deepfake'],
    ['account_takeover', 'Account Takeover'],
    ['network', 'Network Threat'],
    ['api_abuse', 'API Abuse'],
  ];
  const threatCategories = moduleLabels
    .map(([m, label]) => ({ name: label, count: countBy((a) => a.module === m) }))
    .sort((a, b) => b.count - a.count);

  // Build a 24h timeline from alert timestamps
  const now = Date.now();
  const attackTimeline = Array.from({ length: 24 }, (_, i) => {
    const hourStart = now - (23 - i) * 3600 * 1000;
    const hourEnd = hourStart + 3600 * 1000;
    const inHour = alerts.filter((a) => {
      const t = new Date(a.timestamp).getTime();
      return t >= hourStart && t < hourEnd;
    });
    const hour = new Date(hourStart).getHours();
    return {
      hour: `${String(hour).padStart(2, '0')}:00`,
      threats: inHour.length,
      events: Math.max(2, inHour.length + 18 + ((hour * 7) % 11)),
    };
  });

  // Top targeted users/services derived from alerts
  const userHits = new Map<string, { attacks: number; lastAttack: string }>();
  const serviceHits = new Map<string, { attacks: number; severities: Severity[] }>();
  for (const a of alerts) {
    if (a.targetUser) {
      const cur = userHits.get(a.targetUser) ?? { attacks: 0, lastAttack: a.timestamp };
      cur.attacks += 1;
      if (a.timestamp > cur.lastAttack) cur.lastAttack = a.timestamp;
      userHits.set(a.targetUser, cur);
    }
    if (a.targetService) {
      const cur = serviceHits.get(a.targetService) ?? { attacks: 0, severities: [] as Severity[] };
      cur.attacks += 1;
      cur.severities.push(a.severity);
      serviceHits.set(a.targetService, cur);
    }
  }
  const severityRank: Record<Severity, number> = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const topTargetedUsers = [...userHits.entries()]
    .map(([user, v]) => ({ user, attacks: v.attacks, lastAttack: v.lastAttack }))
    .sort((a, b) => b.attacks - a.attacks)
    .slice(0, 5);
  const topTargetedServices = [...serviceHits.entries()]
    .map(([service, v]) => ({
      service,
      attacks: v.attacks,
      riskLevel: v.severities.reduce((worst, s) => (severityRank[s] > severityRank[worst] ? s : worst), 'safe' as Severity),
    }))
    .sort((a, b) => b.attacks - a.attacks)
    .slice(0, 5);

  const incidentSummary = {
    open: db.incidents.filter((i) => i.status === 'open').length,
    investigating: db.incidents.filter((i) => i.status === 'investigating').length,
    contained: db.incidents.filter((i) => i.status === 'contained').length,
    closed: db.incidents.filter((i) => i.status === 'closed').length,
  };

  const recentAlerts = [...alerts].sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 10);
  const totalEventsAnalyzed = 1284 + alerts.length * 37 + db.networkFlows.length * 12 + db.apiLogs.length * 9;

  return {
    totalEventsAnalyzed,
    threatsDetected: alerts.filter((a) => a.severity === 'high' || a.severity === 'critical').length,
    phishingAttempts: countBy((a) => a.module === 'phishing'),
    impersonationAttempts: countBy((a) => a.module === 'impersonation'),
    suspectedDeepfakes: countBy((a) => a.module === 'deepfake'),
    accountTakeoverAttempts: countBy((a) => a.module === 'account_takeover'),
    riskDistribution,
    threatCategories,
    attackTimeline,
    topTargetedUsers,
    topTargetedServices,
    recentAlerts,
    incidentSummary,
  };
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------
export async function mockListAlerts(filters?: {
  severity?: Severity;
  module?: ThreatModule;
  status?: string;
  search?: string;
}): Promise<Alert[]> {
  await jitter();
  let alerts = [...db.alerts];
  if (filters?.severity) alerts = alerts.filter((a) => a.severity === filters.severity);
  if (filters?.module) alerts = alerts.filter((a) => a.module === filters.module);
  if (filters?.status) alerts = alerts.filter((a) => a.status === filters.status);
  if (filters?.search) {
    const q = filters.search.toLowerCase();
    alerts = alerts.filter(
      (a) =>
        a.title.toLowerCase().includes(q) ||
        a.summary.toLowerCase().includes(q) ||
        a.id.toLowerCase().includes(q) ||
        (a.targetUser ?? '').toLowerCase().includes(q)
    );
  }
  return alerts.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

export async function mockGetAlert(id: string): Promise<Alert | null> {
  await jitter();
  return db.alerts.find((a) => a.id === id) ?? null;
}

export function mockAddAlert(alert: Alert): void {
  db.alerts.unshift(alert);
}

// ---------------------------------------------------------------------------
// Analysis wrappers
// ---------------------------------------------------------------------------
export async function mockAnalyzeEmail(sender: string, subject: string, body: string): Promise<AnalysisResult> {
  await jitter();
  return analyzeEmailText(sender, subject, body);
}

export async function mockAnalyzeUrl(url: string): Promise<AnalysisResult> {
  await jitter();
  return analyzeUrl(url);
}

export async function mockAnalyzeImpersonation(message: string, claimedIdentity: string): Promise<AnalysisResult> {
  await jitter();
  return analyzeImpersonation(message, claimedIdentity);
}

export async function mockAnalyzeMedia(file: { name: string; size: number; type: string }): Promise<AnalysisResult> {
  await new Promise((r) => setTimeout(r, 700 + Math.floor(Math.random() * 600)));
  return analyzeMedia(file);
}

export async function mockAnalyzeAuthLog(events: AuthEventInput[]): Promise<AnalysisResult> {
  await jitter();
  return analyzeAuthLog(events);
}

export async function mockAnalyzeNetworkFlow(flows: FlowInput[]): Promise<AnalysisResult> {
  await jitter();
  return analyzeNetworkFlow(flows);
}

export async function mockAnalyzeApiLog(logs: ApiLogInput[]): Promise<AnalysisResult> {
  await jitter();
  return analyzeApiLog(logs);
}

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------
export async function mockListIncidents(): Promise<Incident[]> {
  await jitter();
  return [...db.incidents].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

export async function mockGetIncident(id: string): Promise<Incident | null> {
  await jitter();
  return db.incidents.find((i) => i.id === id) ?? null;
}

export async function mockCreateIncident(alertId: string): Promise<Incident> {
  await jitter();
  const alert = db.alerts.find((a) => a.id === alertId);
  if (!alert) throw new Error(`Alert ${alertId} not found`);
  const existing = db.incidents.find((i) => i.linkedAlertIds.includes(alertId));
  if (existing) return existing;
  const user = DEMO_USER.name;
  const now = new Date().toISOString();
  const incident: Incident = {
    id: `INC-${String(db.incidents.length + 1).padStart(3, '0')}`,
    title: alert.title,
    severity: alert.severity,
    status: 'open',
    assignedTo: undefined,
    linkedAlertIds: [alert.id],
    timeline: [
      {
        id: `EV-${Date.now()}`,
        action: 'Incident Created',
        actor: user,
        timestamp: now,
        details: `Incident opened from alert ${alert.id}: ${alert.summary}`,
      },
    ],
    createdAt: now,
    updatedAt: now,
  };
  db.incidents.unshift(incident);
  addAuditLog({
    userId: DEMO_USER.id,
    userName: DEMO_USER.email,
    action: 'CREATE_INCIDENT',
    resource: incident.id,
    details: `Created incident from alert ${alertId}`,
  });
  return incident;
}

export async function mockUpdateIncidentStatus(id: string, status: IncidentStatus): Promise<Incident> {
  await delay(300);
  const incident = db.incidents.find((i) => i.id === id);
  if (!incident) throw new Error(`Incident ${id} not found`);
  incident.status = status;
  incident.updatedAt = new Date().toISOString();
  incident.timeline.push({
    id: `EV-${Date.now()}`,
    action: 'Status Changed',
    actor: DEMO_USER.name,
    timestamp: incident.updatedAt,
    details: `Status changed to ${status}`,
  });
  addAuditLog({
    userId: DEMO_USER.id,
    userName: DEMO_USER.email,
    action: 'UPDATE_INCIDENT',
    resource: id,
    details: `Status changed to ${status}`,
  });
  return incident;
}

export async function mockAssignIncident(id: string, analyst: string): Promise<Incident> {
  await delay(250);
  const incident = db.incidents.find((i) => i.id === id);
  if (!incident) throw new Error(`Incident ${id} not found`);
  incident.assignedTo = analyst === 'Unassigned' ? undefined : analyst;
  incident.updatedAt = new Date().toISOString();
  incident.timeline.push({
    id: `EV-${Date.now()}`,
    action: 'Assignment Changed',
    actor: DEMO_USER.name,
    timestamp: incident.updatedAt,
    details: `Assigned to ${analyst}`,
  });
  addAuditLog({
    userId: DEMO_USER.id,
    userName: DEMO_USER.email,
    action: 'ASSIGN_INCIDENT',
    resource: id,
    details: `Assigned to ${analyst}`,
  });
  return incident;
}

export async function mockEscalateIncident(id: string): Promise<Incident> {
  await delay(250);
  const incident = db.incidents.find((i) => i.id === id);
  if (!incident) throw new Error(`Incident ${id} not found`);
  incident.updatedAt = new Date().toISOString();
  incident.timeline.push({
    id: `EV-${Date.now()}`,
    action: 'Escalated',
    actor: DEMO_USER.name,
    timestamp: incident.updatedAt,
    details: 'Incident escalated to senior SOC management for priority handling',
  });
  addAuditLog({
    userId: DEMO_USER.id,
    userName: DEMO_USER.email,
    action: 'ESCALATE_INCIDENT',
    resource: id,
    details: 'Incident escalated to management',
  });
  return incident;
}

// ---------------------------------------------------------------------------
// Response actions
// ---------------------------------------------------------------------------
export async function mockListResponseCatalog(): Promise<ResponseActionCatalog[]> {
  await jitter();
  return [...db.responseCatalog];
}

export async function mockListResponseHistory(): Promise<ResponseExecution[]> {
  await jitter();
  return [...db.responseHistory].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

export async function mockExecuteResponse(
  actionId: string,
  target: string,
  approved: boolean
): Promise<ResponseExecution> {
  await jitter();
  const catalog = db.responseCatalog.find((c) => c.id === actionId);
  let name = catalog?.action;
  if (!name) {
    for (const alert of db.alerts) {
      const match = alert.recommendedActions.find((a) => a.id === actionId);
      if (match) {
        name = match.action;
        break;
      }
    }
  }
  if (!name) {
    throw new Error(`Unknown action ${actionId}`);
  }
  if (catalog?.requiresApproval && !approved) {
    throw new Error('This action requires explicit approval before execution');
  }
  const execution: ResponseExecution = {
    id: `EXE-${String(db.responseHistory.length + 1).padStart(3, '0')}`,
    actionId,
    actionName: name,
    target,
    status: approved ? 'executed' : 'executed',
    executedBy: DEMO_USER.email,
    approvedBy: approved ? DEMO_USER.email : undefined,
    timestamp: new Date().toISOString(),
  };
  db.responseHistory.unshift(execution);
  addAuditLog({
    userId: DEMO_USER.id,
    userName: DEMO_USER.email,
    action: 'EXECUTE_ACTION',
    resource: actionId,
    details: `Executed ${name} (simulated) on ${target}`,
  });
  return execution;
}

// ---------------------------------------------------------------------------
// Audit logs
// ---------------------------------------------------------------------------
export async function mockListAuditLogs(): Promise<AuditLog[]> {
  await jitter();
  return [...db.auditLogs].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

// ---------------------------------------------------------------------------
// Raw log listings (login events / network flows / API logs)
// ---------------------------------------------------------------------------
export async function mockListLoginEvents() {
  await jitter();
  return [...db.loginEvents].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

export async function mockListNetworkFlows() {
  await jitter();
  return [...db.networkFlows].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

export async function mockListApiLogs() {
  await jitter();
  return [...db.apiLogs].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

// ---------------------------------------------------------------------------
// SOC Assistant (context-aware canned responses)
// ---------------------------------------------------------------------------
export async function mockAssistantChat(message: string): Promise<string> {
  await delay(600 + Math.floor(Math.random() * 700));
  const q = message.toLowerCase();
  const criticals = db.alerts.filter((a) => a.severity === 'critical');
  const highs = db.alerts.filter((a) => a.severity === 'high');
  const newest = [...db.alerts].sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 5);

  if (q.includes('critical') || q.includes('show critical')) {
    const lines = criticals
      .map((a) => `- ${a.id} [${a.severity.toUpperCase()}] ${a.title} (risk ${a.riskScore})`)
      .join('\n');
    return `There are currently ${criticals.length} critical alerts:\n\n${lines}\n\nI recommend starting with the most recent ones — check the Alerts page and open each for indicators, explanation and recommended actions.`;
  }
  if (q.includes('phishing')) {
    const phish = db.alerts.filter((a) => a.module === 'phishing');
    return `Phishing overview: ${phish.length} phishing alerts in the database. The most severe is "${phish[0]?.title}" (risk ${phish[0]?.riskScore}). Common patterns detected: lookalike sender domains (micr0soft-verify.xyz style substitution), raw-IP credential URLs, and artificial urgency language. The Phishing Analysis page lets you test any email against the heuristic engine — try the provided phishing sample.`;
  }
  if (q.includes('mitre')) {
    const techs = new Map<string, { name: string; tactic: string; count: number }>();
    for (const a of db.alerts) {
      for (const t of a.mitreTechniques) {
        const cur = techs.get(t.id) ?? { name: t.name, tactic: t.tactic, count: 0 };
        cur.count += 1;
        techs.set(t.id, cur);
      }
    }
    const sorted = [...techs.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 8);
    const lines = sorted.map(([id, t]) => `- ${id} ${t.name} (${t.tactic}) — seen ${t.count}x`).join('\n');
    return `MITRE ATT&CK techniques detected across current alerts:\n\n${lines}\n\nFull mappings are available on each alert's "MITRE ATT&CK" tab.`;
  }
  if (q.includes('investigate') || q.includes('first')) {
    const top = [...db.alerts]
      .filter((a) => a.severity === 'critical' || a.severity === 'high')
      .sort((a, b) => b.riskScore - a.riskScore)[0];
    return `I recommend investigating ${top.id} first: "${top.title}" (risk score ${top.riskScore}, ${top.severity}). ${top.summary}. Suggested first step: ${top.recommendedActions[0]?.action ?? 'review indicators'}. Remember that actions marked semi-automatic require your approval before simulated execution.`;
  }
  if (q.includes('incident')) {
    const open = db.incidents.filter((i) => i.status !== 'closed');
    return `Incident summary: ${open.length} active incidents (${db.incidents.filter((i) => i.status === 'open').length} open, ${db.incidents.filter((i) => i.status === 'investigating').length} investigating, ${db.incidents.filter((i) => i.status === 'contained').length} contained). The most recently updated is "${open[0]?.title}". Open the Incidents page to manage assignments and status transitions.`;
  }
  if (q.includes('alert') || q.includes('threat') || q.includes('summarize') || q.includes('today')) {
    const lines = newest.map((a) => `- [${a.severity.toUpperCase()}] ${a.title} (risk ${a.riskScore})`).join('\n');
    return `Threat summary for today: ${db.alerts.length} total alerts, of which ${criticals.length} are critical and ${highs.length} are high severity. Busiest modules are phishing and account takeover. Newest alerts:\n\n${lines}\n\nAsk me "show critical alerts", "list MITRE techniques detected", or "what should I investigate first?" for details.`;
  }
  if (q.includes('help') || q.includes('what can you')) {
    return `I'm the SOC Assistant running in mock mode. I can summarize today's threats, list critical alerts, report on phishing campaigns, enumerate MITRE ATT&CK techniques seen, review incident status, and suggest what to investigate first. I answer from the in-browser mock database, so try the quick action buttons below.`;
  }
  return `I'm the SOC Assistant (mock mode). I can help you with:\n\n- "Summarize today's threats" — overview of alert volume and severity\n- "Show critical alerts" — list of current critical alerts\n- "List MITRE techniques detected" — ATT&CK mapping across alerts\n- "What should I investigate first?" — prioritized recommendation\n- "Incident status" — open incident summary\n\nAll answers come from the local mock database.`;
}

// ---------------------------------------------------------------------------
// Live simulation alert generator
// ---------------------------------------------------------------------------
let simCounter = 0;
const SIM_MODULES: { module: ThreatModule; titles: string[] }[] = [
  { module: 'phishing', titles: ['Phishing Email Detected - {brand} Credential Lure', 'Smishing Campaign Detected Against Finance Team', 'QR-Code Phishing Reference in Email Body'] },
  { module: 'url', titles: ['Lookalike Domain Observed in DNS Logs', 'Suspicious URL Click Blocked by Proxy', 'New Credential-Harvesting Page Indexed'] },
  { module: 'impersonation', titles: ['Executive Impersonation Attempt in Chat', 'Vendor Payment Request Flagged as Fraudulent', 'IT Support Impersonation on Messaging Channel'] },
  { module: 'deepfake', titles: ['Voice Clip Shows Synthetic Speech Indicators', 'Video Call Frame Anomalies Detected', 'AI-Generated Profile Photo Flagged'] },
  { module: 'account_takeover', titles: ['MFA Fatigue Burst on Executive Account', 'Failed Login Burst from Tor Exit', 'Unknown Device Login for Service Account'] },
  { module: 'network', titles: ['Outbound Beaconing to Unknown Host', 'High-Volume Transfer to File-Sharing Domain', 'Suspicious Port Activity on DMZ Host'] },
  { module: 'api_abuse', titles: ['Rate Limit Breach on Auth Endpoint', 'Sequential Enumeration on Public API', 'Repeated 401s from Single Token'] },
];
const SIM_BRANDS = ['Microsoft', 'PayPal', 'Google', 'Amazon', 'Apple'];
const SIM_USERS = ['john.doe@company.com', 'jane.smith@company.com', 'alice.wong@company.com', 'bob.marley@company.com', 'emma.davis@company.com', 'svc-reports'];
const SIM_IPS = ['185.220.101.7', '45.33.32.156', '91.219.237.22', '10.0.4.21', '45.33.49.12'];
const SIM_TECHNIQUES = [
  { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access' },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' },
  { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
  { id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', tactic: 'Command and Control' },
  { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
  { id: 'T1656', name: 'Impersonation', tactic: 'Initial Access' },
];

export function generateSimulatedAlert(): Alert {
  simCounter += 1;
  const entry = SIM_MODULES[simCounter % SIM_MODULES.length];
  const brand = SIM_BRANDS[simCounter % SIM_BRANDS.length];
  const title = entry.titles[simCounter % entry.titles.length].replace('{brand}', brand);
  const risk = 45 + ((simCounter * 17) % 50);
  const severity = getSeverityFromScore(risk);
  const now = new Date().toISOString();
  const recs = severity === 'high' || severity === 'critical'
    ? [
        { id: `RA-S${simCounter}-1`, action: 'Notify Targeted Users', description: 'Send awareness notice to affected recipients', automationLevel: 'manual' as const, requiresApproval: false, priority: 'high' as const },
        { id: `RA-S${simCounter}-2`, action: 'Block Indicator', description: 'Blocklist the primary indicator', automationLevel: 'automatic' as const, requiresApproval: false, priority: 'high' as const },
      ]
    : [
        { id: `RA-S${simCounter}-1`, action: 'Monitor Indicator', description: 'Add to watchlist for correlation', automationLevel: 'manual' as const, requiresApproval: false, priority: 'medium' as const },
      ];
  return {
    id: `ALT-SIM-${String(simCounter).padStart(3, '0')}`,
    title,
    module: entry.module,
    severity,
    riskScore: risk,
    status: 'new',
    summary: `Live simulation alert #${simCounter}: heuristic engine flagged ${entry.module.replace('_', ' ')} activity`,
    indicators: [
      { id: `IND-S${simCounter}-1`, type: 'simulated_event', value: title, severity, description: 'Generated by live simulation for demonstration' },
      { id: `IND-S${simCounter}-2`, type: 'source_ip', value: SIM_IPS[simCounter % SIM_IPS.length], severity: 'medium', description: 'Source associated with the simulated event' },
    ],
    explanation: `This alert was generated by the live simulation feature to demonstrate real-time detection flow. The heuristic engine scored the synthetic event ${risk}/100 (${severity}). Open the alert to review indicators, explanation and recommended actions. This is simulated data, not a real detection.`,
    recommendedActions: recs,
    mitreTechniques: [SIM_TECHNIQUES[simCounter % SIM_TECHNIQUES.length]],
    targetUser: SIM_USERS[simCounter % SIM_USERS.length],
    targetService: 'Simulated Source',
    sourceIp: SIM_IPS[simCounter % SIM_IPS.length],
    timestamp: now,
  };
}

// ---------------------------------------------------------------------------
// Dual-Mode Enforcement (Phases 1-3) — in-browser mock store
// Simulated ActionExecution records + EnforcementPolicy so the org dashboard
// demo works without the backend. Mutations write audit log entries.
// ---------------------------------------------------------------------------

import type {
  ActionExecution,
  ActionListResponse,
  EnforcementPolicy,
  PolicyListResponse,
  PolicyUpdatePayload,
} from '../types';

const nowIso = (minutesAgo = 0) =>
  new Date(Date.now() - minutesAgo * 60_000).toISOString();

let EXEC_SEQ = 0;

function makeExecution(partial: Partial<ActionExecution> & { action_type: string }): ActionExecution {
  EXEC_SEQ += 1;
  const status = partial.status ?? 'pending';
  return {
    id: partial.id ?? `exec-${String(EXEC_SEQ).padStart(4, '0')}`,
    organization_id: 'org-corp-001',
    alert_id: partial.alert_id ?? `ALR-${1200 + EXEC_SEQ}`,
    event_id: partial.event_id ?? `EVT-${1400 + EXEC_SEQ}`,
    action_type: partial.action_type,
    target: partial.target ?? {},
    status,
    execution_mode: partial.execution_mode ?? 'server',
    triggered_by: partial.triggered_by ?? 'api',
    triggered_by_id: partial.triggered_by_id ?? 'email-gateway-01',
    requires_approval: partial.requires_approval ?? false,
    approved_by: partial.approved_by ?? null,
    approved_at: partial.approved_at ?? null,
    rejection_reason: partial.rejection_reason ?? null,
    executed_at:
      partial.executed_at ?? (status === 'success' ? nowIso(5) : null),
    execution_result:
      partial.execution_result ??
      (status === 'success'
        ? { simulated: true, message: 'Action executed (simulated)' }
        : null),
    risk_score: partial.risk_score ?? 80,
    severity: partial.severity ?? 'high',
    threat_type: partial.threat_type ?? partial.module ?? 'phishing',
    module: partial.module ?? 'phishing',
    policy_id: 'policy-mock-001',
    created_at: partial.created_at ?? nowIso(30),
  };
}

const MOCK_ACTION_EXECUTIONS: ActionExecution[] = [
  makeExecution({
    action_type: 'quarantine_email',
    status: 'pending',
    requires_approval: true,
    module: 'phishing',
    severity: 'medium',
    risk_score: 58,
    target: { sender: 'billing@paypa1-support.com', recipient: 'finance@corp.test', subject: 'Invoice #8841 overdue', email_id: 'eml-9012' },
    created_at: nowIso(12),
  }),
  makeExecution({
    action_type: 'revoke_session',
    status: 'pending',
    requires_approval: true,
    module: 'account_takeover',
    severity: 'medium',
    risk_score: 62,
    target: { user_id: 'bob.k', login_attempt_id: 'la-5521' },
    created_at: nowIso(25),
  }),
  makeExecution({
    action_type: 'rate_limit',
    status: 'pending',
    requires_approval: true,
    module: 'api_abuse',
    severity: 'medium',
    risk_score: 55,
    target: { source_ip: '203.0.113.66' },
    created_at: nowIso(48),
  }),
  makeExecution({
    action_type: 'quarantine_email',
    status: 'success',
    module: 'phishing',
    severity: 'high',
    risk_score: 87,
    target: { sender: 'alerts@paypa1-security.com', recipient: 'alice@corp.test', subject: 'URGENT: unauthorized login', email_id: 'eml-8841' },
    created_at: nowIso(95),
  }),
  makeExecution({
    action_type: 'block_url',
    status: 'success',
    module: 'url',
    severity: 'critical',
    risk_score: 92,
    target: { url: 'http://185.220.101.7/secure/login.php' },
    created_at: nowIso(140),
  }),
  makeExecution({
    action_type: 'block_ip',
    status: 'success',
    module: 'network',
    severity: 'high',
    risk_score: 78,
    target: { source_ip: '198.51.100.23', port: 4444 },
    created_at: nowIso(180),
  }),
  makeExecution({
    action_type: 'revoke_session',
    status: 'success',
    module: 'account_takeover',
    severity: 'high',
    risk_score: 81,
    target: { user_id: 'svc.backup', session_id: 'sess-7788' },
    created_at: nowIso(260),
  }),
  makeExecution({
    action_type: 'block_url',
    status: 'unblocked',
    module: 'url',
    severity: 'medium',
    risk_score: 60,
    target: { url: 'http://legacy-cdn.example.com/assets' },
    execution_result: { simulated: true, unblocked_by: 'USR-001', unblocked_at: nowIso(90) },
    created_at: nowIso(320),
  }),
  makeExecution({
    action_type: 'quarantine_email',
    status: 'released',
    module: 'phishing',
    severity: 'medium',
    risk_score: 52,
    target: { sender: 'it-helpdesk@vendor.com', recipient: 'helpdesk@corp.test', subject: 'Password expiry notice' },
    execution_result: { simulated: true, released_by: 'USR-001', released_at: nowIso(110) },
    created_at: nowIso(400),
  }),
  makeExecution({
    action_type: 'block_url',
    status: 'rejected',
    module: 'url',
    severity: 'medium',
    risk_score: 64,
    rejection_reason: 'Marketing campaign link verified with vendor',
    approved_by: 'USR-001',
    target: { url: 'https://promo.partner-mail.com/spring' },
    created_at: nowIso(430),
  }),
  makeExecution({
    action_type: 'allow',
    status: 'skipped',
    execution_mode: 'client',
    module: 'phishing',
    severity: 'low',
    risk_score: 15,
    target: { sender: 'newsletter@university.edu' },
    created_at: nowIso(500),
  }),
];

const MOCK_POLICIES: EnforcementPolicy[] = [
  {
    id: 'policy-mock-001',
    organization_id: 'org-corp-001',
    name: 'Balanced (default)',
    description: 'Auto-block critical/high, require approval for medium.',
    is_active: true,
    phishing_high_threshold: 75,
    phishing_medium_threshold: 40,
    deepfake_high_threshold: 70,
    deepfake_medium_threshold: 50,
    ato_high_threshold: 60,
    ato_medium_threshold: 40,
    network_high_threshold: 70,
    network_medium_threshold: 50,
    impersonation_high_threshold: 70,
    impersonation_medium_threshold: 40,
    action_on_critical: 'block_and_quarantine',
    action_on_high: 'block',
    action_on_medium: 'warn_and_log',
    action_on_low: 'allow',
    auto_execute_critical: true,
    auto_execute_high: true,
    auto_execute_medium: false,
    auto_execute_low: false,
    notify_soc_on_critical: true,
    notify_soc_on_high: true,
    notify_user_on_medium: true,
    created_at: nowIso(60 * 24 * 30),
    updated_at: nowIso(60 * 24 * 2),
  },
  {
    id: 'policy-mock-002',
    organization_id: 'org-corp-001',
    name: 'Strict',
    description: 'Zero-trust posture: enforce everything above the low band.',
    is_active: false,
    phishing_high_threshold: 60,
    phishing_medium_threshold: 30,
    deepfake_high_threshold: 55,
    deepfake_medium_threshold: 35,
    ato_high_threshold: 50,
    ato_medium_threshold: 30,
    network_high_threshold: 55,
    network_medium_threshold: 35,
    impersonation_high_threshold: 55,
    impersonation_medium_threshold: 30,
    action_on_critical: 'block_and_quarantine',
    action_on_high: 'block_and_quarantine',
    action_on_medium: 'block',
    action_on_low: 'warn_and_log',
    auto_execute_critical: true,
    auto_execute_high: true,
    auto_execute_medium: true,
    auto_execute_low: false,
    notify_soc_on_critical: true,
    notify_soc_on_high: true,
    notify_user_on_medium: false,
    created_at: nowIso(60 * 24 * 30),
    updated_at: nowIso(60 * 24 * 7),
  },
];

function simulate(actionType: string): Record<string, unknown> {
  const simId = `sim_${Math.random().toString(16).slice(2, 12)}`;
  if (actionType === 'quarantine_email') return { quarantine_id: `q_${simId}`, simulated: true, message: 'Email moved to quarantine (simulated)' };
  if (actionType === 'block_url') return { block_id: `b_${simId}`, simulated: true, message: 'URL added to blocklist (simulated)' };
  if (actionType === 'block_ip' || actionType === 'drop_packet') return { block_id: `ip_${simId}`, simulated: true, message: 'IP blocked (simulated)' };
  if (actionType === 'revoke_session') return { revoke_id: `r_${simId}`, simulated: true, message: 'Active sessions revoked (simulated)' };
  if (actionType === 'require_mfa') return { mfa_id: `mfa_${simId}`, simulated: true, message: 'MFA challenge issued (simulated)' };
  if (actionType === 'rate_limit') return { rate_limit_id: `rl_${simId}`, simulated: true, message: 'Rate limit applied (simulated)' };
  return { flag_id: `f_${simId}`, simulated: true, message: `Flagged: ${actionType}` };
}

function paginate(items: ActionExecution[], page?: number, pageSize?: number): ActionListResponse {
  const p = page ?? 1;
  const size = pageSize ?? 20;
  return {
    total: items.length,
    page: p,
    page_size: size,
    items: items.slice((p - 1) * size, p * size),
  };
}

export async function mockListActions(params?: {
  status?: string;
  action_type?: string;
  module?: string;
  severity?: string;
  page?: number;
  page_size?: number;
}): Promise<ActionListResponse> {
  await jitter();
  let items = [...MOCK_ACTION_EXECUTIONS];
  if (params?.status) items = items.filter((i) => i.status === params.status);
  if (params?.action_type) items = items.filter((i) => i.action_type === params.action_type);
  if (params?.module) items = items.filter((i) => i.module === params.module);
  if (params?.severity) items = items.filter((i) => i.severity === params.severity);
  items.sort((a, b) => b.created_at.localeCompare(a.created_at));
  return paginate(items, params?.page, params?.page_size);
}

export async function mockGetAction(id: string): Promise<ActionExecution> {
  await jitter();
  const found = MOCK_ACTION_EXECUTIONS.find((i) => i.id === id);
  if (!found) throw new Error(`Action execution ${id} not found`);
  return found;
}

export async function mockApproveAction(id: string, comment?: string): Promise<ActionExecution> {
  await jitter();
  const found = MOCK_ACTION_EXECUTIONS.find((i) => i.id === id);
  if (!found) throw new Error(`Action execution ${id} not found`);
  if (found.status !== 'pending') throw new Error(`Action is not pending (current status: ${found.status})`);
  found.status = 'success';
  found.approved_by = 'USR-001';
  found.approved_at = new Date().toISOString();
  found.executed_at = found.approved_at;
  found.execution_result = simulate(found.action_type);
  addAuditLog({
    userId: 'USR-001',
    userName: 'admin@cyberguard.local',
    action: 'APPROVE_ACTION_EXECUTION',
    resource: id,
    details: comment || `Approved '${found.action_type}'`,
  });
  return found;
}

export async function mockRejectAction(id: string, reason: string): Promise<ActionExecution> {
  await jitter();
  const found = MOCK_ACTION_EXECUTIONS.find((i) => i.id === id);
  if (!found) throw new Error(`Action execution ${id} not found`);
  if (found.status !== 'pending') throw new Error(`Action is not pending (current status: ${found.status})`);
  found.status = 'rejected';
  found.rejection_reason = reason;
  found.approved_by = 'USR-001';
  found.approved_at = new Date().toISOString();
  addAuditLog({
    userId: 'USR-001',
    userName: 'admin@cyberguard.local',
    action: 'REJECT_ACTION_EXECUTION',
    resource: id,
    details: reason,
  });
  return found;
}

export async function mockListQuarantine(page?: number, pageSize?: number): Promise<ActionListResponse> {
  await jitter();
  const items = MOCK_ACTION_EXECUTIONS.filter(
    (i) =>
      ['quarantine_email', 'block_and_quarantine', 'flag_for_review'].includes(i.action_type) &&
      i.status === 'success',
  ).sort((a, b) => b.created_at.localeCompare(a.created_at));
  return paginate(items, page, pageSize);
}

export async function mockReleaseQuarantine(id: string): Promise<ActionExecution> {
  await jitter();
  const found = MOCK_ACTION_EXECUTIONS.find((i) => i.id === id);
  if (!found) throw new Error(`Action execution ${id} not found`);
  if (found.status !== 'success') throw new Error(`Cannot release action with status '${found.status}'`);
  found.status = 'released';
  found.execution_result = {
    ...(found.execution_result ?? {}),
    released_by: 'USR-001',
    released_at: new Date().toISOString(),
  };
  addAuditLog({
    userId: 'USR-001',
    userName: 'admin@cyberguard.local',
    action: 'RELEASE_QUARANTINE',
    resource: id,
    details: 'Quarantined item released',
  });
  return found;
}

export async function mockListBlocklist(page?: number, pageSize?: number): Promise<ActionListResponse> {
  await jitter();
  const items = MOCK_ACTION_EXECUTIONS.filter(
    (i) => ['block_url', 'block_ip', 'drop_packet'].includes(i.action_type) && i.status === 'success',
  ).sort((a, b) => b.created_at.localeCompare(a.created_at));
  return paginate(items, page, pageSize);
}

export async function mockUnblockItem(id: string): Promise<ActionExecution> {
  await jitter();
  const found = MOCK_ACTION_EXECUTIONS.find((i) => i.id === id);
  if (!found) throw new Error(`Action execution ${id} not found`);
  if (found.status !== 'success') throw new Error(`Cannot unblock action with status '${found.status}'`);
  found.status = 'unblocked';
  found.execution_result = {
    ...(found.execution_result ?? {}),
    unblocked_by: 'USR-001',
    unblocked_at: new Date().toISOString(),
  };
  addAuditLog({
    userId: 'USR-001',
    userName: 'admin@cyberguard.local',
    action: 'UNBLOCK_ITEM',
    resource: id,
    details: 'Blocked item removed from blocklist',
  });
  return found;
}

export async function mockListPolicies(): Promise<PolicyListResponse> {
  await jitter();
  const active = MOCK_POLICIES.find((p) => p.is_active) ?? null;
  return {
    policies: [...MOCK_POLICIES],
    active_policy_id: active?.id ?? null,
  };
}

export async function mockGetPolicy(id: string): Promise<EnforcementPolicy> {
  await jitter();
  const found = MOCK_POLICIES.find((p) => p.id === id);
  if (!found) throw new Error(`Policy ${id} not found`);
  return found;
}

export async function mockUpdatePolicy(id: string, updates: PolicyUpdatePayload): Promise<EnforcementPolicy> {
  await jitter();
  const found = MOCK_POLICIES.find((p) => p.id === id);
  if (!found) throw new Error(`Policy ${id} not found`);
  Object.assign(found, updates, { updated_at: new Date().toISOString() });
  addAuditLog({
    userId: 'USR-001',
    userName: 'admin@cyberguard.local',
    action: 'UPDATE_ENFORCEMENT_POLICY',
    resource: id,
    details: `Updated fields: ${Object.keys(updates).join(', ')}`,
  });
  return found;
}

export async function mockActivatePolicy(id: string): Promise<EnforcementPolicy> {
  await jitter();
  const found = MOCK_POLICIES.find((p) => p.id === id);
  if (!found) throw new Error(`Policy ${id} not found`);
  for (const policy of MOCK_POLICIES) policy.is_active = policy.id === id;
  found.updated_at = new Date().toISOString();
  addAuditLog({
    userId: 'USR-001',
    userName: 'admin@cyberguard.local',
    action: 'ACTIVATE_ENFORCEMENT_POLICY',
    resource: id,
    details: `Policy '${found.name}' is now active`,
  });
  return found;
}
