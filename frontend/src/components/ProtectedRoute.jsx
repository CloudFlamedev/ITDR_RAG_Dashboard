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

  const [slowNotice, setSlowNotice] = React.useState(false);

  React.useEffect(() => {
    let t;
    if (isLoading) {
      t = setTimeout(() => setSlowNotice(true), 2500);
    } else {
      setSlowNotice(false);
    }
    return () => clearTimeout(t);
  }, [isLoading]);

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
          textAlign: 'center',
          padding: '20px',
        }}
      >
        <Loader2 className="animate-spin" size={36} color="var(--accent-cyan)" />
        <div style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-main)', letterSpacing: '0.03em' }}>
          Verifying security session...
        </div>
        {slowNotice && (
          <div style={{ fontSize: '0.8rem', color: 'var(--accent-primary)', maxWidth: '360px', lineHeight: '1.4' }}>
            Waking up serverless cloud backend & database pool. This only happens on cold-start; subsequent loads will be instant.
          </div>
        )}
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
