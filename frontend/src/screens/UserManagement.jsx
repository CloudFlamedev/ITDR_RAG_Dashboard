import React, { useState, useEffect } from 'react';
import { apiClient } from '../api/client';
import { useAuth } from '../context/AuthContext';
import {
  Users,
  UserPlus,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Search,
  Lock,
  Mail,
  UserCheck,
  UserX,
  Clock,
  Activity,
  AlertTriangle,
  Loader2,
  CheckCircle,
  X,
  FileText,
} from 'lucide-react';

export const UserManagement = () => {
  const { user: currentUser } = useAuth();
  const [activeTab, setActiveTab] = useState('users'); // 'users' or 'audit'

  // Users state
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [isLoadingUsers, setIsLoadingUsers] = useState(true);
  const [userSearch, setUserSearch] = useState('');
  const [errorMessage, setErrorMessage] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);

  // Modals state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showRoleModal, setShowRoleModal] = useState(null); // target user object
  const [selectedRoles, setSelectedRoles] = useState([]);

  // Create user form state
  const [newEmail, setNewEmail] = useState('');
  const [newName, setNewName] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('Viewer');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Audit Logs state
  const [auditLogs, setAuditLogs] = useState([]);
  const [isLoadingAudit, setIsLoadingAudit] = useState(false);
  const [auditFilter, setAuditFilter] = useState('');

  const fetchUsers = async () => {
    try {
      setIsLoadingUsers(true);
      const data = await apiClient.getUsers({ q: userSearch });
      setUsers(data);
    } catch (err) {
      setErrorMessage(err.response?.data?.detail || 'Failed to fetch users list.');
    } finally {
      setIsLoadingUsers(false);
    }
  };

  const fetchRoles = async () => {
    try {
      const data = await apiClient.getAllRoles();
      setRoles(data);
    } catch (err) {
      console.warn('Failed to fetch system roles:', err);
    }
  };

  const fetchAuditLogs = async () => {
    try {
      setIsLoadingAudit(true);
      const data = await apiClient.getAuditLogs({ action: auditFilter || undefined, limit: 100 });
      setAuditLogs(data);
    } catch (err) {
      setErrorMessage(err.response?.data?.detail || 'Failed to fetch audit logs.');
    } finally {
      setIsLoadingAudit(false);
    }
  };

  useEffect(() => {
    fetchUsers();
    fetchRoles();
  }, []);

  useEffect(() => {
    if (activeTab === 'audit') {
      fetchAuditLogs();
    }
  }, [activeTab, auditFilter]);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setErrorMessage(null);
    try {
      await apiClient.createUser({
        email: newEmail,
        full_name: newName,
        password: newPassword,
        roles: [newRole],
      });
      setSuccessMessage(`User '${newEmail}' provisioned successfully.`);
      setShowCreateModal(false);
      setNewEmail('');
      setNewName('');
      setNewPassword('');
      setNewRole('Viewer');
      fetchUsers();
    } catch (err) {
      setErrorMessage(err.response?.data?.detail || 'Failed to provision user.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleToggleActive = async (targetUser) => {
    if (targetUser.id === currentUser.id) {
      setErrorMessage('You cannot deactivate your own administrative account.');
      return;
    }

    const action = targetUser.is_active ? 'deactivate' : 'reactivate';
    if (!window.confirm(`Are you sure you want to ${action} account ${targetUser.email}?`)) {
      return;
    }

    try {
      await apiClient.updateUser(targetUser.id, { is_active: !targetUser.is_active });
      setSuccessMessage(
        `User ${targetUser.email} ${targetUser.is_active ? 'deactivated (active sessions revoked)' : 'reactivated'}.`
      );
      fetchUsers();
    } catch (err) {
      setErrorMessage(err.response?.data?.detail || 'Failed to update user status.');
    }
  };

  const openRoleModal = (targetUser) => {
    setShowRoleModal(targetUser);
    setSelectedRoles([...targetUser.roles]);
  };

  const handleSaveRoles = async () => {
    if (!showRoleModal) return;
    try {
      await apiClient.updateUserRoles(showRoleModal.id, selectedRoles);
      setSuccessMessage(`Roles updated for ${showRoleModal.email}.`);
      setShowRoleModal(null);
      fetchUsers();
    } catch (err) {
      setErrorMessage(err.response?.data?.detail || 'Failed to update roles.');
    }
  };

  return (
    <div className="page-body">
      {/* Top Banner / Header */}
      <div className="page-header" style={{ marginBottom: '24px' }}>
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Users size={24} color="var(--accent-cyan)" />
            <span>Identity Governance & Access Control</span>
          </h1>
          <p className="page-description">
            Administer enterprise SOC credentials, enforce Role-Based Access Control (RBAC), and review security audit trails.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '12px' }}>
          <button
            onClick={() => setShowCreateModal(true)}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 16px',
              backgroundColor: 'var(--accent-primary)',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              fontSize: '0.85rem',
              fontWeight: 500,
              cursor: 'pointer',
            }}
          >
            <UserPlus size={16} />
            <span>Provision User</span>
          </button>
        </div>
      </div>

      {/* Alert Notices */}
      {errorMessage && (
        <div className="login-alert-banner" style={{ marginBottom: '16px' }}>
          <AlertTriangle size={18} className="login-alert-icon" />
          <div className="login-alert-text">{errorMessage}</div>
          <button onClick={() => setErrorMessage(null)} style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', marginLeft: 'auto' }}>
            <X size={16} />
          </button>
        </div>
      )}

      {successMessage && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            backgroundColor: 'var(--status-covered-bg)',
            border: '1px solid var(--status-covered-border)',
            color: 'var(--status-covered-text)',
            borderRadius: '6px',
            padding: '12px 16px',
            marginBottom: '16px',
            fontSize: '0.875rem',
          }}
        >
          <CheckCircle size={18} />
          <div>{successMessage}</div>
          <button onClick={() => setSuccessMessage(null)} style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', marginLeft: 'auto' }}>
            <X size={16} />
          </button>
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-color)', marginBottom: '20px' }}>
        <button
          onClick={() => setActiveTab('users')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '10px 16px',
            border: 'none',
            borderBottom: activeTab === 'users' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
            backgroundColor: 'transparent',
            color: activeTab === 'users' ? 'var(--accent-cyan)' : 'var(--text-muted)',
            fontWeight: 500,
            fontSize: '0.9rem',
            cursor: 'pointer',
          }}
        >
          <Shield size={16} />
          <span>Provisioned Users ({users.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('audit')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '10px 16px',
            border: 'none',
            borderBottom: activeTab === 'audit' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
            backgroundColor: 'transparent',
            color: activeTab === 'audit' ? 'var(--accent-cyan)' : 'var(--text-muted)',
            fontWeight: 500,
            fontSize: '0.9rem',
            cursor: 'pointer',
          }}
        >
          <Activity size={16} />
          <span>Security Audit Trail</span>
        </button>
      </div>

      {/* Tab 1: Users Table */}
      {activeTab === 'users' && (
        <div style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '8px', overflow: 'hidden' }}>
          {/* Table Search Toolbar */}
          <div style={{ padding: '16px', borderBottom: '1px solid var(--border-color)', display: 'flex', gap: '12px', alignItems: 'center' }}>
            <div style={{ position: 'relative', flex: 1, maxWidth: '360px' }}>
              <Search size={16} style={{ position: 'absolute', left: '12px', top: '10px', color: 'var(--text-muted)' }} />
              <input
                type="text"
                placeholder="Search users by email or name..."
                value={userSearch}
                onChange={(e) => setUserSearch(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && fetchUsers()}
                style={{
                  width: '100%',
                  padding: '8px 12px 8px 36px',
                  borderRadius: '6px',
                  border: '1px solid var(--border-color)',
                  backgroundColor: 'var(--bg-app)',
                  color: 'var(--text-main)',
                  fontSize: '0.85rem',
                }}
              />
            </div>
            <button
              onClick={fetchUsers}
              style={{
                padding: '8px 16px',
                borderRadius: '6px',
                border: '1px solid var(--border-color)',
                backgroundColor: 'var(--bg-surface-alt)',
                color: 'var(--text-main)',
                fontSize: '0.85rem',
                cursor: 'pointer',
              }}
            >
              Filter
            </button>
          </div>

          {/* Table */}
          {isLoadingUsers ? (
            <div style={{ padding: '48px', textAlign: 'center', color: 'var(--text-muted)' }}>
              <Loader2 size={32} className="animate-spin" style={{ margin: '0 auto 12px' }} />
              <div>Loading provisioned identities...</div>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
                <thead>
                  <tr style={{ backgroundColor: 'var(--bg-surface-alt)', borderBottom: '1px solid var(--border-color)', textAlign: 'left' }}>
                    <th style={{ padding: '12px 16px', color: 'var(--text-muted)', fontWeight: 600 }}>User Identity</th>
                    <th style={{ padding: '12px 16px', color: 'var(--text-muted)', fontWeight: 600 }}>Assigned Roles</th>
                    <th style={{ padding: '12px 16px', color: 'var(--text-muted)', fontWeight: 600 }}>Status</th>
                    <th style={{ padding: '12px 16px', color: 'var(--text-muted)', fontWeight: 600 }}>Last Login</th>
                    <th style={{ padding: '12px 16px', color: 'var(--text-muted)', fontWeight: 600, textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '12px 16px' }}>
                        <div style={{ fontWeight: 600, color: 'var(--text-main)' }}>{u.full_name}</div>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{u.email}</div>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                          {u.roles.map((r) => (
                            <span
                              key={r}
                              className={`role-badge role-badge-${r.toLowerCase().replace(' ', '-')}`}
                            >
                              {r}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        {u.is_active ? (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: 'var(--accent-success)', fontSize: '0.8rem', fontWeight: 500 }}>
                            <UserCheck size={14} /> Active
                          </span>
                        ) : (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: 'var(--accent-danger)', fontSize: '0.8rem', fontWeight: 500 }}>
                            <UserX size={14} /> Deactivated
                          </span>
                        )}
                      </td>
                      <td style={{ padding: '12px 16px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                        {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'Never'}
                      </td>
                      <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: '8px' }}>
                          <button
                            onClick={() => openRoleModal(u)}
                            style={{
                              padding: '4px 10px',
                              borderRadius: '4px',
                              border: '1px solid var(--border-color)',
                              backgroundColor: 'transparent',
                              color: 'var(--accent-cyan)',
                              fontSize: '0.75rem',
                              cursor: 'pointer',
                            }}
                          >
                            Edit Roles
                          </button>
                          {u.id !== currentUser.id && (
                            <button
                              onClick={() => handleToggleActive(u)}
                              style={{
                                padding: '4px 10px',
                                borderRadius: '4px',
                                border: '1px solid var(--border-color)',
                                backgroundColor: 'transparent',
                                color: u.is_active ? 'var(--accent-danger)' : 'var(--accent-success)',
                                fontSize: '0.75rem',
                                cursor: 'pointer',
                              }}
                            >
                              {u.is_active ? 'Deactivate' : 'Reactivate'}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Security Audit Trail */}
      {activeTab === 'audit' && (
        <div style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '8px', overflow: 'hidden' }}>
          <div style={{ padding: '16px', borderBottom: '1px solid var(--border-color)', display: 'flex', gap: '12px', alignItems: 'center' }}>
            <select
              value={auditFilter}
              onChange={(e) => setAuditFilter(e.target.value)}
              style={{
                padding: '8px 12px',
                borderRadius: '6px',
                border: '1px solid var(--border-color)',
                backgroundColor: 'var(--bg-app)',
                color: 'var(--text-main)',
                fontSize: '0.85rem',
              }}
            >
              <option value="">All Security Actions</option>
              <option value="login_success">login_success</option>
              <option value="login_failed_bad_password">login_failed_bad_password</option>
              <option value="login_throttled">login_throttled</option>
              <option value="google_login_success">google_login_success</option>
              <option value="github_login_success">github_login_success</option>
              <option value="user_created">user_created</option>
              <option value="user_deactivated">user_deactivated</option>
              <option value="session_revoked">session_revoked</option>
            </select>
            <button
              onClick={fetchAuditLogs}
              style={{
                padding: '8px 16px',
                borderRadius: '6px',
                border: '1px solid var(--border-color)',
                backgroundColor: 'var(--bg-surface-alt)',
                color: 'var(--text-main)',
                fontSize: '0.85rem',
                cursor: 'pointer',
              }}
            >
              Refresh Logs
            </button>
          </div>

          {isLoadingAudit ? (
            <div style={{ padding: '48px', textAlign: 'center', color: 'var(--text-muted)' }}>
              <Loader2 size={32} className="animate-spin" style={{ margin: '0 auto 12px' }} />
              <div>Querying immutable audit logs...</div>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                <thead>
                  <tr style={{ backgroundColor: 'var(--bg-surface-alt)', borderBottom: '1px solid var(--border-color)', textAlign: 'left' }}>
                    <th style={{ padding: '12px 16px', color: 'var(--text-muted)', fontWeight: 600 }}>Timestamp (UTC)</th>
                    <th style={{ padding: '12px 16px', color: 'var(--text-muted)', fontWeight: 600 }}>Security Action</th>
                    <th style={{ padding: '12px 16px', color: 'var(--text-muted)', fontWeight: 600 }}>Subject User ID</th>
                    <th style={{ padding: '12px 16px', color: 'var(--text-muted)', fontWeight: 600 }}>Origin IP</th>
                    <th style={{ padding: '12px 16px', color: 'var(--text-muted)', fontWeight: 600 }}>Telemetry Metadata</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.map((log) => (
                    <tr key={log.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '12px 16px', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                        {new Date(log.timestamp).toISOString()}
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span
                          style={{
                            display: 'inline-block',
                            padding: '2px 8px',
                            borderRadius: '4px',
                            fontSize: '0.75rem',
                            fontFamily: 'var(--font-mono)',
                            backgroundColor: log.action.includes('failed') || log.action.includes('throttled') || log.action.includes('deactivated')
                              ? 'var(--status-exposed-bg)'
                              : 'var(--status-covered-bg)',
                            color: log.action.includes('failed') || log.action.includes('throttled') || log.action.includes('deactivated')
                              ? 'var(--status-exposed-text)'
                              : 'var(--status-covered-text)',
                            border: `1px solid ${
                              log.action.includes('failed') || log.action.includes('throttled') || log.action.includes('deactivated')
                                ? 'var(--status-exposed-border)'
                                : 'var(--status-covered-border)'
                            }`,
                          }}
                        >
                          {log.action}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px', color: 'var(--text-main)' }}>
                        {log.user_id ? `User #${log.user_id}` : 'Unauthenticated / System'}
                      </td>
                      <td style={{ padding: '12px 16px', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                        {log.ip_address || 'Internal'}
                      </td>
                      <td style={{ padding: '12px 16px', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {JSON.stringify(log.metadata)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Modal: Provision New User */}
      {showCreateModal && (
        <div className="modal-backdrop">
          <div className="modal-card" style={{ maxWidth: '480px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h2 style={{ fontSize: '1.2rem', fontWeight: 600, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <UserPlus size={20} color="var(--accent-cyan)" />
                <span>Provision Identity Account</span>
              </h2>
              <button onClick={() => setShowCreateModal(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleCreateUser}>
              <div style={{ marginBottom: '14px' }}>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '4px' }}>
                  Full Name
                </label>
                <input
                  type="text"
                  required
                  placeholder="Security Analyst Name"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-color)',
                    backgroundColor: 'var(--bg-app)',
                    color: 'var(--text-main)',
                  }}
                />
              </div>

              <div style={{ marginBottom: '14px' }}>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '4px' }}>
                  Enterprise Email
                </label>
                <input
                  type="email"
                  required
                  placeholder="analyst@corp.security"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-color)',
                    backgroundColor: 'var(--bg-app)',
                    color: 'var(--text-main)',
                  }}
                />
              </div>

              <div style={{ marginBottom: '14px' }}>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '4px' }}>
                  Temporary Password (min 8 chars)
                </label>
                <input
                  type="password"
                  required
                  minLength={8}
                  placeholder="••••••••••••"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-color)',
                    backgroundColor: 'var(--bg-app)',
                    color: 'var(--text-main)',
                  }}
                />
              </div>

              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '4px' }}>
                  Initial RBAC Role
                </label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-color)',
                    backgroundColor: 'var(--bg-app)',
                    color: 'var(--text-main)',
                  }}
                >
                  <option value="Viewer">Viewer (Read-Only Dashboards & Feeds)</option>
                  <option value="Security Analyst">Security Analyst (Run GenAI Threat Modeling & Ingest)</option>
                  <option value="Admin">Admin (Full Control, User Management & Telemetry)</option>
                </select>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  style={{
                    padding: '8px 16px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-color)',
                    backgroundColor: 'transparent',
                    color: 'var(--text-muted)',
                    cursor: 'pointer',
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '8px 16px',
                    borderRadius: '6px',
                    border: 'none',
                    backgroundColor: 'var(--accent-primary)',
                    color: '#ffffff',
                    fontWeight: 500,
                    cursor: 'pointer',
                  }}
                >
                  {isSubmitting ? <Loader2 size={16} className="animate-spin" /> : <ShieldCheck size={16} />}
                  <span>Provision Account</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Edit Roles */}
      {showRoleModal && (
        <div className="modal-backdrop">
          <div className="modal-card" style={{ maxWidth: '440px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h2 style={{ fontSize: '1.2rem', fontWeight: 600, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Shield size={20} color="var(--accent-cyan)" />
                <span>Assign Roles</span>
              </h2>
              <button onClick={() => setShowRoleModal(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                <X size={18} />
              </button>
            </div>

            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
              Update assigned RBAC roles for <strong>{showRoleModal.email}</strong>:
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '24px' }}>
              {['Admin', 'Security Analyst', 'Viewer'].map((roleName) => (
                <label
                  key={roleName}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                    padding: '10px 14px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-color)',
                    backgroundColor: selectedRoles.includes(roleName) ? 'var(--bg-surface-alt)' : 'transparent',
                    cursor: 'pointer',
                  }}
                >
                  <input
                    type="checkbox"
                    checked={selectedRoles.includes(roleName)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedRoles([...selectedRoles, roleName]);
                      } else {
                        setSelectedRoles(selectedRoles.filter((r) => r !== roleName));
                      }
                    }}
                  />
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-main)' }}>{roleName}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {roleName === 'Admin'
                        ? 'Full system access, user administration & telemetry'
                        : roleName === 'Security Analyst'
                        ? 'Execute threat modeling, ingest feeds, view reports'
                        : 'Read-only access to posture dashboards and feeds'}
                    </div>
                  </div>
                </label>
              ))}
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                type="button"
                onClick={() => setShowRoleModal(null)}
                style={{
                  padding: '8px 16px',
                  borderRadius: '6px',
                  border: '1px solid var(--border-color)',
                  backgroundColor: 'transparent',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleSaveRoles}
                style={{
                  padding: '8px 16px',
                  borderRadius: '6px',
                  border: 'none',
                  backgroundColor: 'var(--accent-primary)',
                  color: '#ffffff',
                  fontWeight: 500,
                  cursor: 'pointer',
                }}
              >
                Save Changes
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default UserManagement;
