import axios from 'axios';

const rawApiBase = import.meta.env.VITE_API_URL || '';
const apiBase = rawApiBase.endsWith('/') ? rawApiBase.slice(0, -1) : rawApiBase;

const api = axios.create({
  baseURL: apiBase,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 120000,
});

// Centralized API client methods
export const apiClient = {
  // System Health
  getSystemStatus: () => api.get('/api/system/status').then(r => r.data),

  // Screen 1: Identity Resilience
  getIdentityResilience: (params = {}) => api.get('/api/reports/identity-resilience', { params }).then(r => r.data),

  // Screen 2: ITDR Coverage Matrix
  getCoverageMatrix: (params = {}) => api.get('/api/coverage-matrix', { params }).then(r => r.data),
  getTtpDetail: (techniqueId) => api.get('/api/coverage-matrix/ttp-detail', { params: { technique_id: techniqueId } }).then(r => r.data),

  // Screen 3: Threat Exposure
  getThreatExposure: (params = {}) => api.get('/api/reports/threat-exposure', { params }).then(r => r.data),

  // Screen 4: Threat Scenarios
  getThreatScenarios: (params = {}) => api.get('/api/reports/threat-scenarios', { params }).then(r => r.data),

  // Screen 5: Threat Feeds & Ingest
  getBulletins: (params = {}) => api.get('/api/identity/bulletins', { params }).then(r => r.data),
  getFeedSources: () => api.get('/api/identity/feeds').then(r => r.data),
  ingestFeed: (payload) => api.post('/api/twin/feeds/ingest', payload).then(r => r.data),

  // Screen 6: Threat Modeling Workspace
  getThreatSamples: () => api.get('/api/threats/samples').then(r => r.data),
  analyzeThreat: (payload) => api.post('/api/threats/analyze', payload).then(r => r.data),

  // Screen 7: Completed Reports
  getReports: (params = {}) => api.get('/api/threats/reports', { params }).then(r => r.data),
  getReportDetail: (reportId) => api.get(`/api/threats/reports/${reportId}`).then(r => r.data),

  // RAG Testing & Health
  searchRag: (payload) => api.post('/api/rag/search', payload).then(r => r.data),
  getRagHealth: () => api.get('/api/rag/health').then(r => r.data),
};

export default apiClient;
