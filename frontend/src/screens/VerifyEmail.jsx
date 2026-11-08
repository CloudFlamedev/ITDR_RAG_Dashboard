import React, { useState, useEffect } from 'react';
import { useSearchParams, Link, useNavigate } from 'react-router-dom';
import { apiClient } from '../api/client';
import {
  CheckCircle2,
  AlertTriangle,
  Mail,
  Loader2,
  ArrowRight,
  ShieldCheck,
  Send,
} from 'lucide-react';

export const VerifyEmail = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const token = searchParams.get('token');
  const initialError = searchParams.get('error');

  const [status, setStatus] = useState(token ? 'verifying' : initialError ? 'error' : 'idle');
  const [errorMsg, setErrorMsg] = useState(initialError || null);
  const [successMsg, setSuccessMsg] = useState(null);

  // Resend form state
  const [resendEmail, setResendEmail] = useState('');
  const [isResending, setIsResending] = useState(false);
  const [resendMsg, setResendMsg] = useState(null);
  const [resendError, setResendError] = useState(null);

  useEffect(() => {
    if (!token) return;

    let isMounted = true;
    setStatus('verifying');
    setErrorMsg(null);

    apiClient
      .verifyEmail(token)
      .then((res) => {
        if (!isMounted) return;
        setStatus('success');
        setSuccessMsg(res.message || 'Email verified successfully! You may now log in.');
      })
      .catch((err) => {
        if (!isMounted) return;
        setStatus('error');
        const detail = err.response?.data?.detail;
        setErrorMsg(detail || err.message || 'Verification link is invalid or has expired.');
      });

    return () => {
      isMounted = false;
    };
  }, [token]);

  const handleResend = async (e) => {
    e.preventDefault();
    if (!resendEmail) return;

    setIsResending(true);
    setResendMsg(null);
    setResendError(null);

    try {
      const res = await apiClient.resendVerification(resendEmail);
      setResendMsg(res.message || 'A fresh verification link has been sent to your email.');
    } catch (err) {
      const detail = err.response?.data?.detail;
      setResendError(detail || err.message || 'Could not resend verification email.');
    } finally {
      setIsResending(false);
    }
  };

  return (
    <div className="login-screen-wrapper">
      <div className="login-card" style={{ maxWidth: '480px' }}>
        <div className="login-header">
          <div className="login-emblem">
            <Mail size={36} color="var(--accent-cyan)" />
          </div>
          <h1 className="login-title">Account Verification</h1>
          <p className="login-subtitle">
            ITDR Platform Identity Activation
          </p>
        </div>

        {/* Verifying Spinner */}
        {status === 'verifying' && (
          <div style={{ textAlign: 'center', padding: '32px 16px' }}>
            <Loader2 size={40} className="animate-spin" style={{ color: 'var(--accent-cyan)', margin: '0 auto 16px' }} />
            <h3 style={{ color: 'var(--text-primary)', marginBottom: '8px' }}>Verifying Token...</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '14px' }}>
              Validating cryptographic token hash with Neon PostgreSQL database.
            </p>
          </div>
        )}

        {/* Verification Success */}
        {status === 'success' && (
          <div style={{ textAlign: 'center', padding: '16px 8px' }}>
            <div
              style={{
                width: '56px',
                height: '56px',
                borderRadius: '50%',
                backgroundColor: 'rgba(34, 197, 94, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 16px',
              }}
            >
              <CheckCircle2 size={32} style={{ color: '#22c55e' }} />
            </div>
            <h2 style={{ color: '#ffffff', fontSize: '20px', marginBottom: '8px' }}>
              Account Activated!
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '14px', lineHeight: '1.5', marginBottom: '24px' }}>
              {successMsg}
            </p>
            <Link
              to="/login"
              className="login-submit-btn"
              style={{
                textDecoration: 'none',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                width: '100%',
              }}
            >
              <ShieldCheck size={16} />
              <span>Proceed to SOC Sign In</span>
            </Link>
          </div>
        )}

        {/* Verification Error */}
        {status === 'error' && (
          <div>
            <div className="login-alert-banner">
              <AlertTriangle size={18} className="login-alert-icon" />
              <div className="login-alert-text">{errorMsg}</div>
            </div>

            <div style={{ marginTop: '24px' }}>
              <h3 style={{ fontSize: '15px', color: 'var(--text-primary)', marginBottom: '8px' }}>
                Need a new verification link?
              </h3>
              <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '16px', lineHeight: '1.4' }}>
                Enter the email address you registered with, and we'll dispatch a fresh verification link.
              </p>

              {resendMsg && (
                <div
                  className="login-alert-banner"
                  style={{
                    borderColor: 'rgba(34, 197, 94, 0.4)',
                    backgroundColor: 'rgba(34, 197, 94, 0.1)',
                    color: '#4ade80',
                    marginBottom: '16px',
                  }}
                >
                  <CheckCircle2 size={16} style={{ color: '#4ade80', flexShrink: 0 }} />
                  <div className="login-alert-text">{resendMsg}</div>
                </div>
              )}

              {resendError && (
                <div className="login-alert-banner" style={{ marginBottom: '16px' }}>
                  <AlertTriangle size={16} className="login-alert-icon" />
                  <div className="login-alert-text">{resendError}</div>
                </div>
              )}

              <form onSubmit={handleResend}>
                <div className="login-field-group">
                  <div className="login-input-wrapper">
                    <Mail size={16} className="login-input-icon" />
                    <input
                      type="email"
                      className="login-input"
                      placeholder="analyst@enterprise.corp"
                      value={resendEmail}
                      onChange={(e) => setResendEmail(e.target.value)}
                      required
                    />
                  </div>
                </div>
                <button
                  type="submit"
                  className="login-submit-btn"
                  disabled={isResending}
                  style={{ marginTop: '8px' }}
                >
                  {isResending ? (
                    <>
                      <Loader2 size={16} className="animate-spin" />
                      <span>Dispatching Link...</span>
                    </>
                  ) : (
                    <>
                      <Send size={16} />
                      <span>Resend Verification Email</span>
                    </>
                  )}
                </button>
              </form>
            </div>
          </div>
        )}

        {/* Idle without token */}
        {status === 'idle' && (
          <div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '14px', marginBottom: '20px', lineHeight: '1.5' }}>
              Please click the link sent to your registered email address to verify your account.
              If you didn't receive it, enter your email below to request a new link:
            </p>

            {resendMsg && (
              <div
                className="login-alert-banner"
                style={{
                  borderColor: 'rgba(34, 197, 94, 0.4)',
                  backgroundColor: 'rgba(34, 197, 94, 0.1)',
                  color: '#4ade80',
                  marginBottom: '16px',
                }}
              >
                <CheckCircle2 size={16} style={{ color: '#4ade80', flexShrink: 0 }} />
                <div className="login-alert-text">{resendMsg}</div>
              </div>
            )}

            {resendError && (
              <div className="login-alert-banner" style={{ marginBottom: '16px' }}>
                <AlertTriangle size={16} className="login-alert-icon" />
                <div className="login-alert-text">{resendError}</div>
              </div>
            )}

            <form onSubmit={handleResend}>
              <div className="login-field-group">
                <div className="login-input-wrapper">
                  <Mail size={16} className="login-input-icon" />
                  <input
                    type="email"
                    className="login-input"
                    placeholder="analyst@enterprise.corp"
                    value={resendEmail}
                    onChange={(e) => setResendEmail(e.target.value)}
                    required
                  />
                </div>
              </div>
              <button
                type="submit"
                className="login-submit-btn"
                disabled={isResending}
                style={{ marginTop: '8px' }}
              >
                {isResending ? (
                  <>
                    <Loader2 size={16} className="animate-spin" />
                    <span>Dispatching Link...</span>
                  </>
                ) : (
                  <>
                    <Send size={16} />
                    <span>Resend Verification Email</span>
                  </>
                )}
              </button>
            </form>
          </div>
        )}

        <div className="login-footer-notice" style={{ textAlign: 'center', marginTop: '24px' }}>
          <Link to="/login" style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>
            &larr; Return to Sign In
          </Link>
        </div>
      </div>
    </div>
  );
};

export default VerifyEmail;
