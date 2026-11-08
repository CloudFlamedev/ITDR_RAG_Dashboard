import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { apiClient } from '../api/client';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [authError, setAuthError] = useState(null);

  const checkAuth = useCallback(async () => {
    try {
      setIsLoading(true);
      setAuthError(null);
      const data = await apiClient.getMe();
      if (data?.user) {
        setUser(data.user);
      } else {
        setUser(null);
      }
    } catch (err) {
      setUser(null);
      // Suppress 401 error on initial check since user might not be logged in yet
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    checkAuth();

    // Listen for session expiration events dispatched by Axios interceptor
    const handleSessionExpired = () => {
      setUser(null);
    };

    window.addEventListener('itdr:session-expired', handleSessionExpired);
    return () => {
      window.removeEventListener('itdr:session-expired', handleSessionExpired);
    };
  }, [checkAuth]);

  const login = async (email, password) => {
    setAuthError(null);
    try {
      const data = await apiClient.login(email, password);
      if (data?.user) {
        setUser(data.user);
        return data.user;
      }
      throw new Error('Authentication succeeded but user record was missing.');
    } catch (err) {
      const detail =
        err.response?.data?.detail ||
        err.message ||
        'Authentication failed. Please verify credentials.';
      setAuthError(detail);
      throw new Error(detail);
    }
  };

  const logout = async () => {
    try {
      await apiClient.logout();
    } catch (err) {
      console.warn('Logout API error:', err);
    } finally {
      setUser(null);
      sessionStorage.removeItem('itdr_csrf');
    }
  };

  const hasRole = (roleName) => {
    if (!user || !user.roles) return false;
    return user.roles.includes(roleName);
  };

  const hasPermission = (permissionKey) => {
    if (!user) return false;
    // Admins implicitly possess all permissions
    if (user.roles?.includes('Admin')) return true;
    return user.permissions?.includes(permissionKey);
  };

  const isAdmin = Boolean(user?.roles?.includes('Admin'));
  const isAnalyst = Boolean(user?.roles?.includes('Security Analyst') || isAdmin);
  const isViewer = Boolean(user?.roles?.includes('Viewer'));

  const value = {
    user,
    isAuthenticated: Boolean(user),
    isLoading,
    authError,
    login,
    logout,
    checkAuth,
    hasRole,
    hasPermission,
    isAdmin,
    isAnalyst,
    isViewer,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;
