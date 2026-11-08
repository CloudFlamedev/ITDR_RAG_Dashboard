import axios from 'axios';

const rawApiBase = import.meta.env.VITE_API_URL || '';
const apiBase = rawApiBase.endsWith('/') ? rawApiBase.slice(0, -1) : rawApiBase;

export function getCookie(name) {
  if (typeof document === 'undefined') return null;
  const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[2]) : null;
}

const api = axios.create({
  baseURL: apiBase,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Enforce sending and receiving HttpOnly session cookies
  timeout: 120000,
});

// Request Interceptor: Attach CSRF Token on mutating HTTP requests
api.interceptors.request.use(
  (config) => {
    const method = (config.method || '').toUpperCase();
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      const csrfToken = getCookie('itdr_csrf') || sessionStorage.getItem('itdr_csrf');
      if (csrfToken) {
        config.headers['X-CSRF-Token'] = csrfToken;
      }
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response Interceptor: Automatically store fresh CSRF tokens and broadcast session expiration
api.interceptors.response.use(
  (response) => {
    if (response?.data?.csrf_token) {
      sessionStorage.setItem('itdr_csrf', response.data.csrf_token);
    }
    return response;
  },
  (error) => {
    if (error.response && error.response.status === 401) {
      const url = error.config?.url || '';
      // Avoid redirect looping when checking /api/auth/login or /api/auth/me during initial boot
      if (!url.includes('/api/auth/login')) {
        window.dispatchEvent(new CustomEvent('itdr:session-expired'));
      }
    }
    return Promise.reject(error);
  }
);

// Centralized API client methods
export const apiClient = {
  // Authentication & Session
  login: (email, password) => api.post('/api/auth/login', { email, password }).then((r) => r.data),
  logout: () => api.post('/api/auth/logout').then((r) => r.data),
  getMe: () => api.get('/api/auth/me').then((r) => r.data),
  getCsrf: () => api.get('/api/auth/csrf').then((r) => r.data),

  // User Management (Admin only)
  getUsers: (params = {}) => api.get('/api/users', { params }).then((r) => r.data),
  createUser: (payload) => api.post('/api/users', payload).then((r) => r.data),
  getUser: (id) => api.get(`/api/users/${id}`).then((r) => r.data),
  updateUser: (id, payload) => api.patch(`/api/users/${id}`, payload).then((r) => r.data),
  updateUserRoles: (id, roles) => api.patch(`/api/users/${id}/roles`, { roles }).then((r) => r.data),
  deactivateUser: (id) => api.delete(`/api/users/${id}`).then((r) => r.data),
  getAllRoles: () => api.get('/api/users/roles/all').then((r) => r.data),
  getAuditLogs: (params = {}) => api.get('/api/users/audit/logs', { params }).then((r) => r.data),

  // System Health
  getSystemStatus: () => api.get('/api/system/status').then((r) => r.data),

  // Screen 1: Identity Resilience
  getIdentityResilience: (params = {}) => api.get('/api/reports/identity-resilience', { params }).then((r) => r.data),

  // Screen 2: ITDR Coverage Matrix
  getCoverageMatrix: (params = {}) => api.get('/api/coverage-matrix', { params }).then((r) => r.data),
  getTtpDetail: (techniqueId) => api.get('/api/coverage-matrix/ttp-detail', { params: { technique_id: techniqueId } }).then((r) => r.data),

  // Screen 3: Threat Exposure
  getThreatExposure: (params = {}) => api.get('/api/reports/threat-exposure', { params }).then((r) => r.data),

  // Screen 4: Threat Scenarios
  getThreatScenarios: (params = {}) => api.get('/api/reports/threat-scenarios', { params }).then((r) => r.data),

  // Screen 5: Threat Feeds & Ingest
  getBulletins: (params = {}) => api.get('/api/identity/bulletins', { params }).then((r) => r.data),
  getFeedSources: () => api.get('/api/identity/feeds').then((r) => r.data),
  ingestFeed: (payload) => api.post('/api/twin/feeds/ingest', payload).then((r) => r.data),

  // Screen 6: Threat Modeling Workspace
  getThreatSamples: () => api.get('/api/threats/samples').then((r) => r.data),
  analyzeThreat: (payload) => api.post('/api/threats/analyze', payload).then((r) => r.data),

  // Screen 7: Completed Reports
  getReports: (params = {}) => api.get('/api/threats/reports', { params }).then((r) => r.data),
  getReportDetail: (reportId) => api.get(`/api/threats/reports/${reportId}`).then((r) => r.data),

  // RAG Testing & Health
  searchRag: (payload) => api.post('/api/rag/search', payload).then((r) => r.data),
  getRagHealth: () => api.get('/api/rag/health').then((r) => r.data),
};

export default apiClient;
