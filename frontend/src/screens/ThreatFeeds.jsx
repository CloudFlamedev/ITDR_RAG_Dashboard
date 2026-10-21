import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import apiClient from '../api/client';
import MetricCard from '../components/MetricCard';
import { Rss, PlusCircle, Search, RefreshCw, ExternalLink, ArrowRight, ShieldAlert } from 'lucide-react';

export const ThreatFeeds = () => {
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [sources, setSources] = useState(null);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);

  // Ingest form state
  const [ingestTitle, setIngestTitle] = useState('');
  const [ingestSource, setIngestSource] = useState('CISA / Threat Intel');
  const [ingestContent, setIngestContent] = useState('');
  const [ingestUrl, setIngestUrl] = useState('');
  const [ingestSeverity, setIngestSeverity] = useState('High');
  const [ingesting, setIngesting] = useState(false);
  const [ingestError, setIngestError] = useState(null);

  const fetchBulletins = () => {
    setLoading(true);
    apiClient
      .getBulletins({ status: statusFilter, search: searchQuery || undefined })
      .then((res) => setData(res))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  };

  const fetchSources = () => {
    apiClient.getFeedSources().then((res) => setSources(res)).catch((err) => console.error(err));
  };

  useEffect(() => {
    fetchBulletins();
    fetchSources();
  }, [statusFilter]);

  const handleSearch = (e) => {
    e.preventDefault();
    fetchBulletins();
  };

  const handleIngestSubmit = async (e) => {
    e.preventDefault();
    setIngesting(true);
    setIngestError(null);
    try {
      await apiClient.ingestFeed({
        title: ingestTitle,
        source: ingestSource,
        content: ingestContent,
        url: ingestUrl || undefined,
        severity: ingestSeverity,
      });
      setIsModalOpen(false);
      setIngestTitle('');
      setIngestContent('');
      setIngestUrl('');
      fetchBulletins();
    } catch (err) {
      setIngestError(err.response?.data?.detail || 'Failed to ingest feed advisory.');
    } finally {
      setIngesting(false);
    }
  };

  const handleAnalyzeInWorkspace = (bulletin) => {
    // Navigate to Threat Modeling Workspace with preloaded advisory text
    navigate('/threat-modeling', { state: { advisoryText: bulletin.description, title: bulletin.title } });
  };

  const kpis = data?.kpis || {};

  return (
    <div className="page-body">
      {/* Header */}
      <div style={{ marginBottom: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h1 style={{ fontSize: '22px', fontWeight: '800', color: 'var(--text-main)' }}>
            Threat Intelligence Feeds
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Aggregated threat intelligence feeds from CISA, Microsoft, Okta, Wiz, and internal SOC sensors.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="btn btn-secondary" onClick={() => fetchBulletins()} title="Refresh CTI feeds">
            <RefreshCw size={15} />
            <span>Sync Now</span>
          </button>
          <button className="btn btn-primary" onClick={() => setIsModalOpen(true)}>
            <PlusCircle size={15} />
            <span>Ingest Advisory</span>
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid-cols-4">
        <MetricCard
          label="Total CTI Bulletins"
          value={kpis.total_bulletins || 0}
          subtext="Processed intelligence records"
          icon={Rss}
          color="var(--accent-primary)"
        />
        <MetricCard
          label="New / Unprocessed"
          value={kpis.new_count || 0}
          subtext="Awaiting threat modeling triage"
          icon={ShieldAlert}
          color="var(--accent-cyan)"
        />
        <MetricCard
          label="Analyzed Reports"
          value={kpis.analyzed_count || 0}
          subtext="Structured threat models generated"
          icon={ShieldAlert}
          color="var(--accent-teal)"
        />
        <MetricCard
          label="Needing Review"
          value={kpis.review_count || 0}
          subtext="Flagged for analyst verification"
          icon={ShieldAlert}
          color="var(--accent-warning)"
        />
      </div>

      {/* Filter and Search Bar */}
      <div className="card" style={{ marginBottom: '20px', padding: '16px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
          {/* Status Filter Buttons */}
          <div className="view-segmented-group">
            {['ALL', 'New', 'Analyzed', 'Review'].map((st) => (
              <button
                key={st}
                className={`view-segment-btn ${statusFilter === st ? 'active' : ''}`}
                onClick={() => setStatusFilter(st)}
              >
                {st}
              </button>
            ))}
          </div>

          {/* Search Form */}
          <form onSubmit={handleSearch} style={{ display: 'flex', gap: '8px', flex: 1, maxWidth: '420px' }}>
            <input
              type="text"
              placeholder="Search bulletin ID, keyword, or actor..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                flex: 1,
                padding: '6px 12px',
                borderRadius: '6px',
                border: '1px solid var(--border-color)',
                backgroundColor: 'var(--bg-surface-alt)',
                color: 'var(--text-main)',
                fontSize: '13px',
              }}
            />
            <button type="submit" className="btn btn-secondary" style={{ padding: '6px 12px' }}>
              <Search size={14} />
            </button>
          </form>
        </div>
      </div>

      {/* CTI Bulletins Table */}
      <div className="card" style={{ padding: '0', overflow: 'hidden' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: '130px' }}>Bulletin ID</th>
              <th>Advisory Title & Narrative</th>
              <th style={{ width: '160px' }}>Source</th>
              <th style={{ width: '100px' }}>Status</th>
              <th style={{ width: '140px' }}>Related TTPs</th>
              <th style={{ width: '110px', textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                  Loading threat intelligence bulletins...
                </td>
              </tr>
            ) : data?.bulletins?.length > 0 ? (
              data.bulletins.map((b) => (
                <tr key={b.id}>
                  <td>
                    <span style={{ fontWeight: '700', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--accent-primary)' }}>
                      {b.bulletin_id}
                    </span>
                    {b.is_demo && <span className="badge badge-demo" style={{ display: 'block', marginTop: '2px', width: 'fit-content' }}>DEMO</span>}
                  </td>
                  <td>
                    <div style={{ fontWeight: '600', color: 'var(--text-main)', marginBottom: '2px' }}>
                      {b.title}
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: '1.4' }}>
                      {b.description?.slice(0, 140)}...
                    </div>
                  </td>
                  <td>
                    <span style={{ fontSize: '12.5px', color: 'var(--text-main)', fontWeight: '500' }}>
                      {b.source}
                    </span>
                  </td>
                  <td>
                    <span
                      className={`badge ${
                        b.status === 'Analyzed'
                          ? 'badge-covered'
                          : b.status === 'Review'
                          ? 'badge-demo'
                          : 'badge-exposed'
                      }`}
                    >
                      {b.status}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                      {b.related_ttps?.slice(0, 3).map((ttp) => (
                        <span key={ttp} className="badge badge-demo" style={{ fontSize: '10.5px' }}>
                          {ttp}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      className="btn btn-primary"
                      style={{ padding: '4px 10px', fontSize: '11.5px' }}
                      onClick={() => handleAnalyzeInWorkspace(b)}
                      title="Load into Threat Modeling Workspace"
                    >
                      <span>Analyze</span>
                      <ArrowRight size={12} />
                    </button>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                  No threat bulletins matched the active filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Ingest Advisory Modal */}
      {isModalOpen && (
        <div className="drawer-backdrop" onClick={() => setIsModalOpen(false)}>
          <div
            className="card"
            style={{ width: '560px', maxWidth: '90vw', margin: 'auto', maxHeight: '90vh', overflowY: 'auto' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="card-title">
              <span>Ingest Threat Advisory / Bulletin</span>
              <button
                onClick={() => setIsModalOpen(false)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
              >
                ✕
              </button>
            </div>

            {ingestError && (
              <div style={{ padding: '10px 12px', borderRadius: '6px', backgroundColor: 'var(--status-exposed-bg)', border: '1px solid var(--status-exposed-border)', color: 'var(--status-exposed-text)', fontSize: '12px', marginBottom: '16px' }}>
                {ingestError}
              </div>
            )}

            <form onSubmit={handleIngestSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', marginBottom: '4px' }}>
                  Advisory Title *
                </label>
                <input
                  type="text"
                  required
                  value={ingestTitle}
                  onChange={(e) => setIngestTitle(e.target.value)}
                  placeholder="e.g. Threat Actor Observed Abusing OAuth App Consent"
                  style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', backgroundColor: 'var(--bg-surface-alt)', color: 'var(--text-main)', fontSize: '13px' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', marginBottom: '4px' }}>
                    Publishing Source *
                  </label>
                  <input
                    type="text"
                    required
                    value={ingestSource}
                    onChange={(e) => setIngestSource(e.target.value)}
                    placeholder="e.g. CISA, Okta, Internal SOC"
                    style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', backgroundColor: 'var(--bg-surface-alt)', color: 'var(--text-main)', fontSize: '13px' }}
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', marginBottom: '4px' }}>
                    Severity Level
                  </label>
                  <select
                    value={ingestSeverity}
                    onChange={(e) => setIngestSeverity(e.target.value)}
                    className="filter-select"
                    style={{ width: '100%', padding: '8px 12px' }}
                  >
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', marginBottom: '4px' }}>
                  Source Reference URL (SSRF Protected)
                </label>
                <input
                  type="url"
                  value={ingestUrl}
                  onChange={(e) => setIngestUrl(e.target.value)}
                  placeholder="https://example.com/advisory"
                  style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', backgroundColor: 'var(--bg-surface-alt)', color: 'var(--text-main)', fontSize: '13px' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', marginBottom: '4px' }}>
                  Advisory Narrative / Incident Logs *
                </label>
                <textarea
                  required
                  rows={6}
                  value={ingestContent}
                  onChange={(e) => setIngestContent(e.target.value)}
                  placeholder="Paste raw advisory text, execution narrative, or security event logs..."
                  style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', backgroundColor: 'var(--bg-surface-alt)', color: 'var(--text-main)', fontSize: '13px', fontFamily: 'var(--font-mono)' }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
                <button type="button" className="btn btn-secondary" onClick={() => setIsModalOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={ingesting}>
                  {ingesting ? 'Validating & Ingesting...' : 'Submit & Parse TTPs'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatFeeds;
