import React from 'react';
import { NavLink } from 'react-router-dom';
import { useFilters } from '../context/FilterContext';
import { useAuth } from '../context/AuthContext';
import {
  ShieldAlert,
  ShieldCheck,
  Grid,
  Radio,
  Workflow,
  Rss,
  Terminal,
  FileText,
  Users,
  LogOut,
  X,
  User,
} from 'lucide-react';

export const Sidebar = () => {
  const { sidebarOpen, closeSidebar } = useFilters();
  const { user, logout, hasPermission, isAdmin } = useAuth();

  return (
    <>
      {/* Mobile Drawer Backdrop */}
      {sidebarOpen && (
        <div
          className="sidebar-backdrop"
          onClick={closeSidebar}
          aria-hidden="true"
        />
      )}

      <aside className={`sidebar ${sidebarOpen ? 'sidebar-open' : ''}`}>
        {/* Branding & Close Button */}
        <div className="sidebar-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div className="sidebar-logo">
              <ShieldAlert size={20} />
            </div>
            <div>
              <div className="sidebar-title">ITDR Platform</div>
              <div className="sidebar-subtitle">Enterprise Posture v2.0</div>
            </div>
          </div>

          {/* Close button visible on mobile */}
          <button
            className="sidebar-close-btn"
            onClick={closeSidebar}
            aria-label="Close navigation sidebar"
            title="Close navigation"
          >
            <X size={18} />
          </button>
        </div>

        {/* Navigation Links */}
        <nav className="sidebar-nav" style={{ flex: 1 }}>
          {/* SECTION 1 */}
          <div className="nav-section-title">Identity Threat Insights</div>

          <NavLink
            to="/"
            end
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            onClick={closeSidebar}
          >
            <ShieldCheck size={16} />
            <span>Overview (Resilience)</span>
          </NavLink>

          <NavLink
            to="/coverage-matrix"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            onClick={closeSidebar}
          >
            <Grid size={16} />
            <span>ITDR Coverage Matrix</span>
          </NavLink>

          <NavLink
            to="/threat-exposure"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            onClick={closeSidebar}
          >
            <Radio size={16} />
            <span>Identity Threat Exposure</span>
          </NavLink>

          <NavLink
            to="/threat-scenarios"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            onClick={closeSidebar}
          >
            <Workflow size={16} />
            <span>Identity Threat Scenarios</span>
          </NavLink>

          {/* SECTION 2 */}
          <div className="nav-section-title" style={{ marginTop: '24px' }}>
            Identity Threat Detection & Response Portal
          </div>

          <NavLink
            to="/feeds"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            onClick={closeSidebar}
          >
            <Rss size={16} />
            <span>Threat Intelligence Feeds</span>
          </NavLink>

          <NavLink
            to="/threat-modeling"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            onClick={closeSidebar}
          >
            <Terminal size={16} />
            <span>Threat Modeling Workspace</span>
          </NavLink>

          <NavLink
            to="/reports"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            onClick={closeSidebar}
          >
            <FileText size={16} />
            <span>Completed Intelligence Reports</span>
          </NavLink>

          {/* SECTION 3: ADMIN ONLY */}
          {(isAdmin || hasPermission('users:manage')) && (
            <>
              <div className="nav-section-title" style={{ marginTop: '24px' }}>
                Identity Governance & Access
              </div>

              <NavLink
                to="/users"
                className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                onClick={closeSidebar}
              >
                <Users size={16} />
                <span>User Management & Audit</span>
              </NavLink>
            </>
          )}
        </nav>

        {/* User Profile & Logout Footer */}
        {user && (
          <div className="sidebar-user-footer">
            <div className="user-profile-info">
              <div className="user-avatar-circle">
                <User size={16} />
              </div>
              <div className="user-text-meta">
                <div className="user-name-label">{user.full_name || 'Operator'}</div>
                <div className="user-email-label">{user.email}</div>
                <div className="user-roles-chips">
                  {user.roles?.map((role) => (
                    <span
                      key={role}
                      className={`role-badge role-badge-${role.toLowerCase().replace(' ', '-')}`}
                    >
                      {role}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <button
              onClick={logout}
              className="user-logout-btn"
              title="Terminate encrypted SOC session"
              aria-label="Logout"
            >
              <LogOut size={16} />
            </button>
          </div>
        )}
      </aside>
    </>
  );
};

export default Sidebar;
