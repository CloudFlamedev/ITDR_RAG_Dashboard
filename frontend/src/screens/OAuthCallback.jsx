import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ShieldCheck, AlertTriangle, Loader2 } from 'lucide-react';

export const OAuthCallback = () => {
  const [searchParams] = useSearchParams();
  const { checkAuth } = useAuth();
  const navigate = useNavigate();
  const [errorMessage, setErrorMessage] = useState(null);

  useEffect(() => {
    const processCallback = async () => {
      const error = searchParams.get('error');
      if (error) {
        setErrorMessage(error);
        setTimeout(() => {
          navigate(`/login?error=${encodeURIComponent(error)}`, { replace: true });
        }, 2000);
        return;
      }

      try {
        await checkAuth();
        navigate('/', { replace: true });
      } catch (err) {
        const msg = err.message || 'Failed to finalize OAuth session.';
        setErrorMessage(msg);
        setTimeout(() => {
          navigate(`/login?error=${encodeURIComponent(msg)}`, { replace: true });
        }, 2500);
      }
    };

    processCallback();
  }, [checkAuth, navigate, searchParams]);

  return (
    <div className="login-screen-wrapper">
      <div className="login-card" style={{ textAlign: 'center', padding: '48px 32px' }}>
        {errorMessage ? (
          <>
            <div style={{ color: 'var(--accent-danger)', marginBottom: '16px' }}>
              <AlertTriangle size={48} style={{ margin: '0 auto' }} />
            </div>
            <h2 style={{ fontSize: '1.25rem', marginBottom: '8px', color: 'var(--text-main)' }}>
              Authentication Verification Failed
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '24px' }}>
              {errorMessage}
            </p>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
              Redirecting back to login...
            </div>
          </>
        ) : (
          <>
            <div style={{ color: 'var(--accent-cyan)', marginBottom: '16px' }}>
              <Loader2 size={48} className="animate-spin" style={{ margin: '0 auto' }} />
            </div>
            <h2 style={{ fontSize: '1.25rem', marginBottom: '8px', color: 'var(--text-main)' }}>
              Validating Identity Token
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
              Establishing encrypted SOC session and synchronizing RBAC privileges...
            </p>
          </>
        )}
      </div>
    </div>
  );
};

export default OAuthCallback;
