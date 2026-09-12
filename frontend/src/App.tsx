import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import MainLayout from './components/layout/MainLayout';
import ProtectedRoute from './components/layout/ProtectedRoute';
import RoleGuard from './components/layout/RoleGuard';
import Landing from './pages/Landing';
import Login from './pages/Login';
import ResetPassword from './pages/ResetPassword';
import OrganizationManagement from './pages/OrganizationManagement';
import AdminUsers from './pages/AdminUsers';
import ComingSoon from './pages/ComingSoon';
import EmailConnectors from './pages/EmailConnectors';
import BlockedSenders from './pages/BlockedSenders';
import { useAuthStore } from './store/authStore';
import Dashboard from './pages/Dashboard';
import ApprovalQueue from './pages/ApprovalQueue';
import QuarantineQueue from './pages/QuarantineQueue';
import BlockList from './pages/BlockList';
import ActionLog from './pages/ActionLog';
import PolicyManagement from './pages/PolicyManagement';
import PhishingAnalysis from './pages/PhishingAnalysis';
import UrlAnalysis from './pages/UrlAnalysis';
import ImpersonationAnalysis from './pages/ImpersonationAnalysis';
import DeepfakeAnalysis from './pages/DeepfakeAnalysis';
import AccountTakeover from './pages/AccountTakeover';
import NetworkThreats from './pages/NetworkThreats';
import Alerts from './pages/Alerts';
import AlertDetail from './pages/AlertDetail';
import Incidents from './pages/Incidents';
import IncidentDetail from './pages/IncidentDetail';
import ResponseActions from './pages/ResponseActions';
import AuditLogs from './pages/AuditLogs';
import Reports from './pages/Reports';
import Settings from './pages/Settings';

/**
 * Organization features are frozen server-side (ORG_ENABLED=false). While the
 * flag is off, org routes render the ComingSoon placeholder instead of the
 * real pages; they reactivate automatically once the backend flips the flag.
 */
function OrgFeature({ children }: { children: React.ReactNode }) {
  const orgEnabled = useAuthStore((s) => s.orgEnabled);
  if (!orgEnabled) return <ComingSoon />;
  return <>{children}</>;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route
          element={
            <ProtectedRoute>
              <MainLayout />
            </ProtectedRoute>
          }
        >
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/email-connectors" element={<EmailConnectors />} />
          <Route path="/blocked-senders" element={<BlockedSenders />} />
          <Route path="/approvals" element={<ApprovalQueue />} />
          <Route path="/quarantine" element={<QuarantineQueue />} />
          <Route path="/blocklist" element={<BlockList />} />
          <Route path="/action-log" element={<ActionLog />} />
          <Route
            path="/policies"
            element={
              <RoleGuard minimumRole="admin">
                <PolicyManagement />
              </RoleGuard>
            }
          />
          <Route
            path="/organization"
            element={
              <OrgFeature>
                <OrganizationManagement />
              </OrgFeature>
            }
          />
          <Route
            path="/admin/users"
            element={
              <OrgFeature>
                <RoleGuard minimumRole="admin">
                  <AdminUsers />
                </RoleGuard>
              </OrgFeature>
            }
          />
          <Route path="/phishing" element={<PhishingAnalysis />} />
          <Route path="/url-analysis" element={<UrlAnalysis />} />
          <Route path="/impersonation" element={<ImpersonationAnalysis />} />
          <Route path="/deepfake" element={<DeepfakeAnalysis />} />
          <Route path="/account-takeover" element={<AccountTakeover />} />
          <Route path="/network-threats" element={<NetworkThreats />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/alerts/:id" element={<AlertDetail />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route path="/response-actions" element={<ResponseActions />} />
          <Route path="/audit-logs" element={<AuditLogs />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/settings" element={<Settings />} />
        </Route>
        <Route path="/" element={<Landing />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
