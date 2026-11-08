import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ShieldX, ArrowLeft, ShieldAlert } from 'lucide-react';

export const AccessDenied = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const requiredPermission = location.state?.requiredPermission;
  const requiredRole = location.state?.requiredRole;

  return (
    <div className="page-body">
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '60vh',
          textAlign: 'center',
          maxWidth: '540px',
          margin: '0 auto',
          padding: '32px 16px',
        }}
      >
        <div
          style={{
            width: '64px',
            height: '64px',
            borderRadius: '50%',
            backgroundColor: 'var(--status-exposed-bg)',
            border: '1px solid var(--status-exposed-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--accent-danger)',
            marginBottom: '20px',
          }}
        >
          <ShieldX size={36} />
        </div>

        <h1 style={{ fontSize: '1.5rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '8px' }}>
          403 Forbidden: Insufficient Privileges
        </h1>

        <p style={{ color: 'var(--text-muted)', fontSize: '0.95rem', lineHeight: '1.6', marginBottom: '24px' }}>
          Your enterprise identity account does not possess the required RBAC authorization to access this operational resource.
        </p>

        {/* Diagnostic Card */}
        <div
          style={{
            width: '100%',
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border-color)',
            borderRadius: '8px',
            padding: '16px 20px',
            textAlign: 'left',
            marginBottom: '28px',
            fontSize: '0.85rem',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
            <span style={{ color: 'var(--text-muted)' }}>Authenticated Identity:</span>
            <span style={{ fontWeight: 500, color: 'var(--text-main)' }}>{user?.email || 'Unknown'}</span>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
            <span style={{ color: 'var(--text-muted)' }}>Active Roles:</span>
            <span style={{ color: 'var(--accent-cyan)', fontWeight: 500 }}>
              {user?.roles?.join(', ') || 'None'}
            </span>
          </div>

          {requiredPermission && (
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Required Permission:</span>
              <span style={{ color: 'var(--accent-danger)', fontFamily: 'var(--font-mono)' }}>
                {requiredPermission}
              </span>
            </div>
          )}

          {requiredRole && (
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Required Role:</span>
              <span style={{ color: 'var(--accent-danger)' }}>{requiredRole}</span>
            </div>
          )}
        </div>

        <button
          onClick={() => navigate('/', { replace: true })}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '10px 20px',
            backgroundColor: 'var(--accent-primary)',
            color: '#ffffff',
            border: 'none',
            borderRadius: '6px',
            fontWeight: 500,
            fontSize: '0.9rem',
            cursor: 'pointer',
          }}
        >
          <ArrowLeft size={16} />
          <span>Return to Identity Resilience Overview</span>
        </button>
      </div>
    </div>
  );
};

export default AccessDenied;
