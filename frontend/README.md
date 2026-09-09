# 🛡️ CYBERGUARD — Frontend SOC Command Center & Landing Page

Next-generation, responsive Security Operations Center (SOC) dashboard and landing portal for **CYBERGUARD**, built with **React 18**, **Vite 5**, **TypeScript**, **Tailwind CSS**, and **Zustand**.

---

## ⚡ Highlights & User Experience

* **🌐 Modern Landing Page (`/`)**: High-converting, cyberpunk-styled portal featuring live defense metrics, interactive threat module showcases, high-level architecture diagrams, and quick access to authentication.
* **🔐 Multi-Method Authentication**:
  * **OAuth 2.0 Providers**: One-click sign-in with **Google** and **GitHub** powered by Supabase Auth.
  * **Email & Password**: Direct enterprise credential authentication with JWT session persistence.
  * **In-Browser Mock Mode**: Instant demo access (`admin@cyberguard.local` / `demo1234`) with zero backend dependency.
* **📊 Cyber Defense SOC Dashboard (`/dashboard`)**:
  * Real-time attack velocity graphs, MITRE ATT&CK distribution, and incident status breakdown.
  * Live simulation toggle generating streaming alerts every 20 seconds.
* **🔍 Interactive Forensic Analyzers**:
  * Specialized views for Email Phishing, Lexical URL Analysis, BEC Impersonation, Account Takeover, Network/API C2 Abuse, and Deepfake Media Forensics.
* **⚡ SOAR Automation & Incident Management**:
  * Playbook action catalog with approval-gated human-in-the-loop triggers and immutable audit logging.

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd frontend
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
```

| Variable | Default | Purpose |
|---|---|---|
| `VITE_API_BASE_URL` | `http://localhost:8000/api/v1` | URL of the FastAPI backend |
| `VITE_USE_MOCK` | `false` | `false` connects to real backend; `true` uses in-browser mock engine |
| `VITE_SUPABASE_URL` | `https://YOUR-PROJECT.supabase.co` | Supabase project URL for Auth & OAuth |
| `VITE_SUPABASE_ANON_KEY` | `your-anon-key` | Supabase public anonymous key |

### 3. Run Development Server

```bash
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

### 4. Build for Production

```bash
npm run build
npm run preview
```

---

## 🗺️ Application Page Map

| Route | Page Component | Description |
|---|---|---|
| `/` | `LandingPage.tsx` | Platform overview, telemetry metrics, detection capabilities, and CTA |
| `/login` | `Login.tsx` | OAuth (Google/GitHub) and password-based authentication modal |
| `/dashboard` | `Dashboard.tsx` | High-level SOC metrics, attack timelines, donut breakdown, recent alerts |
| `/phishing` | `Phishing.tsx` | Email header, body, and lookalike domain heuristic analyzer |
| `/url-analysis` | `UrlAnalysis.tsx` | Lexical URL parsing, entropy scores, and redirect simulation |
| `/impersonation`| `Impersonation.tsx` | BEC, executive impersonation, and wire transfer pressure analysis |
| `/deepfake` | `Deepfake.tsx` | Media forensic file upload (ELA, frame inspection, WAV analysis) |
| `/account-takeover` | `AccountTakeover.tsx` | Impossible travel, credential stuffing, and brute force telemetry |
| `/network-threats` | `NetworkThreats.tsx` | NetFlow inspection, C2 beaconing, and anomalous outbound transfers |
| `/alerts` | `Alerts.tsx` | Searchable, filterable threat alert queue with severity badges |
| `/alerts/:id` | `AlertDetail.tsx` | Deep threat view: risk gauge, indicators, MITRE tags, and XAI intel |
| `/incidents` | `Incidents.tsx` | Incident queue with severity, assignee, and SLA tracking |
| `/incidents/:id`| `IncidentDetail.tsx`| Escalation controls, containment history, and linked alerts |
| `/response-actions`| `ResponseActions.tsx`| SOAR catalog, automated playbooks, and execution history |
| `/audit-logs` | `AuditLogs.tsx` | Immutable chronological trail of analyst and automated actions |
| `/reports` | `Reports.tsx` | Security intelligence summaries with JSON/CSV export capabilities |
| `/settings` | `Settings.tsx` | User profile, active workspace mode, and risk thresholds |

---

## 🎨 Design System & Theme

* **Palette**: Tailored dark SOC palette with `slate-950` backgrounds, `cyan-500` high-contrast accents, and color-coded risk bands (`emerald-500` safe, `amber-500` medium, `red-500` critical).
* **Responsive Layout**: Collapsible sidebar, sticky topbar with active user profile, workspace badge, live simulation controls, and floating SOC Assistant chat drawer.

