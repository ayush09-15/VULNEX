import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import AppShell from './components/layout/AppShell';
import ErrorBoundary from './components/common/ErrorBoundary';
import OverviewPage from './pages/OverviewPage';
import RepositoriesPage from './pages/RepositoriesPage';
import ScanPage from './pages/ScanPage';
import FindingsPage from './pages/FindingsPage';
import RemediationPage from './pages/RemediationPage';
import ReportsPage from './pages/ReportsPage';
import SettingsPage from './pages/SettingsPage';

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<AppShell />}>
            <Route index element={<Navigate to="/overview" replace />} />
            <Route path="overview" element={<OverviewPage />} />
            <Route path="repositories" element={<RepositoriesPage />} />
            <Route path="scan" element={<ScanPage />} />
            <Route path="findings" element={<FindingsPage />} />
            <Route path="remediation" element={<RemediationPage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/overview" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  );
}
