import React, { createContext, useContext, useState, useEffect } from 'react';
import apiClient from '../api/client';

const FilterContext = createContext();

export const FilterProvider = ({ children }) => {
  // Global Top Bar States
  const [viewMode, setViewMode] = useState(() => localStorage.getItem('itdr_view_mode') || 'ClientReq');
  const [clientRestriction, setClientRestriction] = useState('ALL');
  const [itdrScope, setItdrScope] = useState('ITDR Scope Only');
  const [theme, setTheme] = useState(() => localStorage.getItem('itdr_theme') || 'light');
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const toggleSidebar = () => setSidebarOpen(prev => !prev);
  const closeSidebar = () => setSidebarOpen(false);

  // Subsystem Telemetry Heartbeat
  const [systemStatus, setSystemStatus] = useState(null);
  const [statusLoading, setStatusLoading] = useState(true);

  // Sync theme to root DOM
  useEffect(() => {
    localStorage.setItem('itdr_theme', theme);
    document.documentElement.setAttribute('data-theme', theme);
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [theme]);

  // Sync viewMode to localStorage
  useEffect(() => {
    localStorage.setItem('itdr_view_mode', viewMode);
  }, [viewMode]);

  // Poll system status
  const fetchStatus = async () => {
    try {
      const data = await apiClient.getSystemStatus();
      setSystemStatus(data);
    } catch (err) {
      console.warn('System status fetch failed:', err);
    } finally {
      setStatusLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 30000); // 30s heartbeat
    return () => clearInterval(interval);
  }, []);

  const toggleTheme = () => {
    setTheme(prev => (prev === 'light' ? 'dark' : 'light'));
  };

  const getFilterParams = () => ({
    client_restriction: clientRestriction,
    itdr_scope: itdrScope,
    view_mode: viewMode,
  });

  return (
    <FilterContext.Provider
      value={{
        viewMode,
        setViewMode,
        clientRestriction,
        setClientRestriction,
        itdrScope,
        setItdrScope,
        theme,
        toggleTheme,
        sidebarOpen,
        setSidebarOpen,
        toggleSidebar,
        closeSidebar,
        systemStatus,
        statusLoading,
        refreshStatus: fetchStatus,
        getFilterParams,
      }}
    >
      {children}
    </FilterContext.Provider>
  );
};

export const useFilters = () => useContext(FilterContext);
