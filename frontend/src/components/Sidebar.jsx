import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  Grid,
  Radio,
  Workflow,
  Rss,
  Terminal,
  FileText,
} from 'lucide-react';

export const Sidebar = () => {
  return (
    <aside className="sidebar">
      {/* Branding */}
      <div className="sidebar-header">
        <div className="sidebar-logo">
          <ShieldAlert size={20} />
        </div>
        <div>
          <div className="sidebar-title">ITDR Platform</div>
          <div className="sidebar-subtitle">Enterprise Posture v2.0</div>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="sidebar-nav">
        {/* SECTION 1 */}
        <div className="nav-section-title">Identity Threat Insights</div>

        <NavLink to="/" end className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <ShieldCheck size={16} />
          <span>Overview (Resilience)</span>
        </NavLink>

        <NavLink to="/coverage-matrix" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <Grid size={16} />
          <span>ITDR Coverage Matrix</span>
        </NavLink>

        <NavLink to="/threat-exposure" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <Radio size={16} />
          <span>Identity Threat Exposure</span>
        </NavLink>

        <NavLink to="/threat-scenarios" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <Workflow size={16} />
          <span>Identity Threat Scenarios</span>
        </NavLink>

        {/* SECTION 2 */}
        <div className="nav-section-title" style={{ marginTop: '24px' }}>
          Identity Threat Detection & Response Portal
        </div>

        <NavLink to="/feeds" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <Rss size={16} />
          <span>Threat Intelligence Feeds</span>
        </NavLink>

        <NavLink to="/threat-modeling" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <Terminal size={16} />
          <span>Threat Modeling Workspace</span>
        </NavLink>

        <NavLink to="/reports" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <FileText size={16} />
          <span>Completed Intelligence Reports</span>
        </NavLink>
      </nav>
    </aside>
  );
};

export default Sidebar;
