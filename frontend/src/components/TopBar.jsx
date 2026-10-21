import React from 'react';
import { useFilters } from '../context/FilterContext';
import { Sun, Moon, Database, Cpu, Sparkles, Layers, Activity } from 'lucide-react';

export const TopBar = () => {
  const {
    viewMode,
    setViewMode,
    clientRestriction,
    setClientRestriction,
    itdrScope,
    setItdrScope,
    theme,
    toggleTheme,
    systemStatus,
  } = useFilters();

  const dbStatus = systemStatus?.subsystems?.database?.status === 'Online';
  const pgvectorStatus = systemStatus?.subsystems?.pgvector?.enabled;
  const xaiStatus = systemStatus?.subsystems?.xai_grok?.status === 'Online';
  const hfStatus = systemStatus?.subsystems?.huggingface?.status === 'Online';
  const kbCount = systemStatus?.subsystems?.knowledge_base?.techniques_count || 867;

  return (
    <header className="topbar">
      <div className="topbar-controls">
        {/* View Mode Switcher */}
        <div className="view-segmented-group" title="Pivots across 4 viewports (Persisted in localStorage)">
          {['ClientReq', 'MVP1', 'MVP2', 'MVP3'].map((mode) => (
            <button
              key={mode}
              className={`view-segment-btn ${viewMode === mode ? 'active' : ''}`}
              onClick={() => setViewMode(mode)}
            >
              {mode}
            </button>
          ))}
        </div>

        {/* Client Restriction Filter */}
        <select
          className="filter-select"
          value={clientRestriction}
          onChange={(e) => setClientRestriction(e.target.value)}
          title="Enforces multi-tenancy boundaries"
        >
          <option value="ALL">Client: ALL</option>
          <option value="Client Restricted">Client: Restricted</option>
          <option value="Unrestricted">Client: Unrestricted</option>
        </select>

        {/* ITDR Scope Restriction Filter */}
        <select
          className="filter-select"
          value={itdrScope}
          onChange={(e) => setItdrScope(e.target.value)}
          title="Filters universal MITRE techniques to isolate identity-plane attack vectors"
        >
          <option value="ALL">Scope: ALL Enterprise</option>
          <option value="ITDR Scope Only">Scope: ITDR Scope Only</option>
          <option value="Non-ITDR">Scope: Non-ITDR</option>
        </select>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        {/* Heartbeat Status Indicators */}
        <div className="heartbeat-strip">
          {/* Database */}
          <div className="status-pill" title={`PostgreSQL: ${systemStatus?.subsystems?.database?.version || 'Connected'}`}>
            <span className={`status-dot ${dbStatus ? 'dot-green' : 'dot-red'}`} />
            <Database size={12} />
            <span>DB: {dbStatus ? 'Neon/PG' : 'Offline'}</span>
          </div>

          {/* pgvector */}
          <div className="status-pill" title={systemStatus?.subsystems?.pgvector?.note || 'pgvector extension'}>
            <span className={`status-dot ${pgvectorStatus ? 'dot-green' : 'dot-amber'}`} />
            <Layers size={12} />
            <span>Vector: {pgvectorStatus ? 'pgvector' : 'Fallback'}</span>
          </div>

          {/* Grok xAI */}
          <div className="status-pill" title={`Model: ${systemStatus?.subsystems?.xai_grok?.model || 'grok-4.7'}`}>
            <span className={`status-dot ${xaiStatus ? 'dot-green' : 'dot-blue'}`} />
            <Sparkles size={12} />
            <span>Grok: {xaiStatus ? 'Online' : 'Grounded'}</span>
          </div>

          {/* Hugging Face */}
          <div className="status-pill" title={`Embedding: ${systemStatus?.subsystems?.huggingface?.model || 'BAAI/bge-small-en-v1.5'}`}>
            <span className={`status-dot ${hfStatus ? 'dot-green' : 'dot-blue'}`} />
            <Cpu size={12} />
            <span>HF: {hfStatus ? 'Online' : '384d'}</span>
          </div>

          {/* KB Sync */}
          <div className="status-pill" title="Synchronized ATT&CK and D3FEND records">
            <Activity size={12} />
            <span>KB: {kbCount} TTPs</span>
          </div>
        </div>

        {/* Theme Toggle */}
        <button
          className="theme-toggle-btn"
          onClick={toggleTheme}
          title={`Switch to ${theme === 'light' ? 'Dark Cyber SOC' : 'Executive Light'} mode`}
          aria-label="Toggle Theme"
        >
          {theme === 'light' ? <Moon size={16} /> : <Sun size={16} />}
        </button>
      </div>
    </header>
  );
};

export default TopBar;
