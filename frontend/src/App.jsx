import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { FilterProvider } from './context/FilterContext';
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Sidebar from './components/Sidebar';
import TopBar from './components/TopBar';

import Login from './screens/Login';
import OAuthCallback from './screens/OAuthCallback';
import AccessDenied from './screens/AccessDenied';
import UserManagement from './screens/UserManagement';

import ResilienceDashboard from './screens/ResilienceDashboard';
import CoverageMatrix from './screens/CoverageMatrix';
import ThreatExposure from './screens/ThreatExposure';
import ThreatScenarios from './screens/ThreatScenarios';
import ThreatFeeds from './screens/ThreatFeeds';
import ThreatModelingWorkspace from './screens/ThreatModelingWorkspace';
import CompletedReports from './screens/CompletedReports';

const AuthenticatedLayout = ({ children }) => {
  return (
    <div className="app-container">
      <Sidebar />
      <div className="main-content">
        <TopBar />
        {children}
      </div>
    </div>
  );
};

export const App = () => {
  return (
    <AuthProvider>
      <FilterProvider>
        <BrowserRouter>
          <Routes>
            {/* Public Authentication Routes */}
            <Route path="/login" element={<Login />} />
            <Route path="/auth/callback" element={<OAuthCallback />} />

            {/* Protected Routes inside SOC Console Layout */}
            <Route
              path="/"
              element={
                <ProtectedRoute requiredPermission="dashboard:read">
                  <AuthenticatedLayout>
                    <ResilienceDashboard />
                  </AuthenticatedLayout>
                </ProtectedRoute>
              }
            />

            <Route
              path="/coverage-matrix"
              element={
                <ProtectedRoute requiredPermission="matrix:read">
                  <AuthenticatedLayout>
                    <CoverageMatrix />
                  </AuthenticatedLayout>
                </ProtectedRoute>
              }
            />

            <Route
              path="/threat-exposure"
              element={
                <ProtectedRoute requiredPermission="dashboard:read">
                  <AuthenticatedLayout>
                    <ThreatExposure />
                  </AuthenticatedLayout>
                </ProtectedRoute>
              }
            />

            <Route
              path="/threat-scenarios"
              element={
                <ProtectedRoute requiredPermission="dashboard:read">
                  <AuthenticatedLayout>
                    <ThreatScenarios />
                  </AuthenticatedLayout>
                </ProtectedRoute>
              }
            />

            <Route
              path="/feeds"
              element={
                <ProtectedRoute requiredPermission="feeds:read">
                  <AuthenticatedLayout>
                    <ThreatFeeds />
                  </AuthenticatedLayout>
                </ProtectedRoute>
              }
            />

            <Route
              path="/threat-modeling"
              element={
                <ProtectedRoute requiredPermission="threats:read">
                  <AuthenticatedLayout>
                    <ThreatModelingWorkspace />
                  </AuthenticatedLayout>
                </ProtectedRoute>
              }
            />

            <Route
              path="/reports"
              element={
                <ProtectedRoute requiredPermission="threats:read">
                  <AuthenticatedLayout>
                    <CompletedReports />
                  </AuthenticatedLayout>
                </ProtectedRoute>
              }
            />

            <Route
              path="/users"
              element={
                <ProtectedRoute requiredPermission="users:manage">
                  <AuthenticatedLayout>
                    <UserManagement />
                  </AuthenticatedLayout>
                </ProtectedRoute>
              }
            />

            <Route
              path="/access-denied"
              element={
                <ProtectedRoute>
                  <AuthenticatedLayout>
                    <AccessDenied />
                  </AuthenticatedLayout>
                </ProtectedRoute>
              }
            />

            {/* Catch-all fallback */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </FilterProvider>
    </AuthProvider>
  );
};

export default App;
