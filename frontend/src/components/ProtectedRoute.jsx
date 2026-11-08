import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ShieldCheck, Loader2 } from 'lucide-react';

export const ProtectedRoute = ({
  children,
  requiredPermission,
  requiredRole,
}) => {
  const { isAuthenticated, isLoading, hasPermission, hasRole } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '60vh',
          gap: '16px',
          color: 'var(--text-muted)',
        }}
      >
        <Loader2 className="animate-spin" size={36} color="var(--accent-cyan)" />
        <div style={{ fontSize: '0.9rem', letterSpacing: '0.05em' }}>
          Verifying security session...
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requiredPermission && !hasPermission(requiredPermission)) {
    return <Navigate to="/access-denied" state={{ from: location, requiredPermission }} replace />;
  }

  if (requiredRole && !hasRole(requiredRole)) {
    return <Navigate to="/access-denied" state={{ from: location, requiredRole }} replace />;
  }

  return children;
};

export default ProtectedRoute;
