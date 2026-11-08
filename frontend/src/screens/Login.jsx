import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation, useSearchParams, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { apiClient, getApiBase } from '../api/client';
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  Mail,
  Eye,
  EyeOff,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  ExternalLink,
  Send,
} from 'lucide-react';

export const Login = () => {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  const [email, setEmail] = useState(searchParams.get('email') || '');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState(searchParams.get('error') || null);
  const [isVerifiedNotice, setIsVerifiedNotice] = useState(searchParams.get('verified') === 'true');
  const [isRegisteredNotice, setIsRegisteredNotice] = useState(searchParams.get('registered') === 'true');

  const destination = location.state?.from?.pathname || '/';

  useEffect(() => {
    if (isAuthenticated) {
      navigate(destination, { replace: true });
    }
  }, [isAuthenticated, navigate, destination]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!email || !password) {
      setErrorMsg('Please provide both email address and password.');
      return;
    }

    setIsLoading(true);
    setErrorMsg(null);

    try {
      await login(email, password);
      navigate(destination, { replace: true });
    } catch (err) {
      setErrorMsg(err.message || 'Authentication failed. Please verify your credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleOAuthLogin = (provider) => {
    const apiBase = getApiBase();
    window.location.href = `${apiBase}/api/auth/oauth/${provider}/login`;
  };

  return (
    <div className="login-screen-wrapper">
      <div className="login-card">
        {/* Header with Emblem */}
        <div className="login-header">
          <div className="login-emblem">
            <ShieldAlert size={36} color="var(--accent-cyan)" />
          </div>
          <h1 className="login-title">ITDR SOC Platform</h1>
          <p className="login-subtitle">
            Identity Threat Detection & Response Intelligence
          </p>
        </div>

        {/* Registration Success Banner */}
        {isRegisteredNotice && (
          <div
            className="login-alert-banner"
            style={{
              borderColor: 'rgba(34, 197, 94, 0.4)',
              backgroundColor: 'rgba(34, 197, 94, 0.1)',
              color: '#4ade80',
              marginBottom: '16px',
            }}
          >
            <CheckCircle2 size={18} className="login-alert-icon" style={{ color: '#4ade80' }} />
            <div className="login-alert-text">
              Your account has been created successfully. You can now log in.
            </div>
          </div>
        )}

        {/* Verification Success Banner */}
        {isVerifiedNotice && (
          <div
            className="login-alert-banner"
            style={{
              borderColor: 'rgba(34, 197, 94, 0.4)',
              backgroundColor: 'rgba(34, 197, 94, 0.1)',
              color: '#4ade80',
              marginBottom: '16px',
            }}
          >
            <CheckCircle2 size={18} className="login-alert-icon" style={{ color: '#4ade80' }} />
            <div className="login-alert-text">
              Email verified successfully! You may now sign in with your credentials.
            </div>
          </div>
        )}

        {/* Error Alert Banner */}
        {errorMsg && (
          <div className="login-alert-banner">
            <AlertTriangle size={18} className="login-alert-icon" />
            <div className="login-alert-text">
              <div>{errorMsg}</div>
            </div>
          </div>
        )}

        {/* Email / Password Form */}
        <form onSubmit={handleSubmit} className="login-form">
          <div className="login-field-group">
            <label className="login-label" htmlFor="login-email">
              Identity Identifier (Email)
            </label>
            <div className="login-input-wrapper">
              <Mail size={16} className="login-input-icon" />
              <input
                id="login-email"
                type="email"
                className="login-input"
                placeholder="analyst@enterprise.corp"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                required
              />
            </div>
          </div>

          <div className="login-field-group">
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <label className="login-label" htmlFor="login-password">
                Password
              </label>
            </div>
            <div className="login-input-wrapper">
              <Lock size={16} className="login-input-icon" />
              <input
                id="login-password"
                type={showPassword ? 'text' : 'password'}
                className="login-input"
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
              <button
                type="button"
                className="login-toggle-pwd"
                onClick={() => setShowPassword(!showPassword)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            className="login-submit-btn"
            disabled={isLoading}
          >
            {isLoading ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                <span>Authenticating Credentials...</span>
              </>
            ) : (
              <>
                <ShieldCheck size={16} />
                <span>Authenticate to SOC Console</span>
              </>
            )}
          </button>
        </form>

        {/* Divider */}
        <div className="login-divider">
          <span>OR CONTINUE WITH SINGLE SIGN-ON</span>
        </div>

        {/* Third-Party Social Login Buttons */}
        <div className="login-social-buttons">
          <button
            type="button"
            className="social-btn google-btn"
            onClick={() => handleOAuthLogin('google')}
          >
            <svg className="social-icon" viewBox="0 0 24 24" width="18" height="18">
              <path
                fill="#4285F4"
                d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.8-2.4 3.65v3.05h3.88c2.27-2.09 3.66-5.17 3.66-9.14z"
              />
              <path
                fill="#34A853"
                d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.27v3.15C3.25 21.35 7.33 24 12 24z"
              />
              <path
                fill="#FBBC05"
                d="M5.28 14.27a7.17 7.17 0 0 1 0-4.54V6.58H1.27a11.96 11.96 0 0 0 0 10.84l4.01-3.15z"
              />
              <path
                fill="#EA4335"
                d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.33 0 3.25 2.65 1.27 6.58l4.01 3.15c.95-2.83 3.6-4.98 6.72-4.98z"
              />
            </svg>
            <span>Continue with Google</span>
          </button>

          <button
            type="button"
            className="social-btn github-btn"
            onClick={() => handleOAuthLogin('github')}
          >
            <svg className="social-icon" viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
              <path
                fillRule="evenodd"
                clipRule="evenodd"
                d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
              />
            </svg>
            <span>Continue with GitHub</span>
          </button>
        </div>

        {/* Public Registration Link & Notice */}
        <div className="login-footer-notice" style={{ textAlign: 'center' }}>
          Don't have an account?{' '}
          <Link to="/register" style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>
            Create an Account
          </Link>
          <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-muted)' }}>
            Public demo accounts are provisioned with Demo Analyst access to explore the SOC platform.
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
