import React, { useEffect, useState } from 'react';
import { useFilters } from '../context/FilterContext';
import apiClient from '../api/client';
import MetricCard from '../components/MetricCard';
import TechniqueDrawer from '../components/TechniqueDrawer';
import { ShieldCheck, AlertCircle, Layers, SlidersHorizontal, ToggleLeft, ToggleRight } from 'lucide-react';

export const CoverageMatrix = () => {
  const { getFilterParams } = useFilters();
  const [viewScope, setViewScope] = useState('identity'); // "identity" or "enterprise"
  const [statusFilter, setStatusFilter] = useState('all'); // "all", "covered", "uncovered"
  const [activeTools, setActiveTools] = useState([
    'CrowdStrike',
    'Defender for Identity',
    'Okta',
    'Wiz',
    'In-House',
    'Third-Party',
  ]);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedTechnique, setSelectedTechnique] = useState(null);

  const filterParams = getFilterParams();

  const fetchMatrix = () => {
    setLoading(true);
    const params = {
      ...filterParams,
      view_scope: viewScope,
      status: statusFilter,
      tools: activeTools,
    };
    apiClient
      .getCoverageMatrix(params)
      .then((res) => setData(res))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchMatrix();
  }, [viewScope, statusFilter, activeTools.length, filterParams.client_restriction, filterParams.itdr_scope]);

  const toggleTool = (toolName) => {
    setActiveTools((prev) =>
      prev.includes(toolName) ? prev.filter((t) => t !== toolName) : [...prev, toolName]
    );
  };

  const summary = data?.summary || {};

  return (
    <div className="page-body">
      {/* Header & Global Scope Switchers */}
      <div style={{ marginBottom: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h1 style={{ fontSize: '22px', fontWeight: '800', color: 'var(--text-main)' }}>
            ITDR Coverage Matrix
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Multi-vendor detection mapping across ATT&CK techniques, identity tools, and defense gaps.
          </p>
        </div>

        {/* Scope and Filter Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          {/* Identity vs Enterprise View Switch */}
          <div className="view-segmented-group">
            <button
              className={`view-segment-btn ${viewScope === 'identity' ? 'active' : ''}`}
              onClick={() => setViewScope('identity')}
            >
              Identity View
            </button>
            <button
              className={`view-segment-btn ${viewScope === 'enterprise' ? 'active' : ''}`}
              onClick={() => setViewScope('enterprise')}
            >
              Enterprise View
            </button>
          </div>

          {/* Status Filter */}
          <div className="view-segmented-group">
            <button
              className={`view-segment-btn ${statusFilter === 'all' ? 'active' : ''}`}
              onClick={() => setStatusFilter('all')}
            >
              All
            </button>
            <button
              className={`view-segment-btn ${statusFilter === 'covered' ? 'active' : ''}`}
              onClick={() => setStatusFilter('covered')}
            >
              Covered
            </button>
            <button
              className={`view-segment-btn ${statusFilter === 'uncovered' ? 'active' : ''}`}
              onClick={() => setStatusFilter('uncovered')}
            >
              Uncovered (Gaps)
            </button>
          </div>
        </div>
      </div>

      {/* Top 4 KPI Cards */}
      <div className="grid-cols-4">
        <MetricCard
          label="Coverage Metric"
          value={`${summary.covered_techniques || 0} / ${summary.total_in_scope || 0}`}
          subtext="Techniques with mapped defense"
          icon={ShieldCheck}
          color="var(--accent-teal)"
        />
        <MetricCard
          label="Rule Metric"
          value={summary.active_rules_deployed || 0}
          subtext="Active detection rules deployed"
          icon={Layers}
          color="var(--accent-primary)"
        />
        <MetricCard
          label="Global Coverage Rate"
          value={`${summary.coverage_rate || 0}%`}
          subtext="(Covered / Total in Scope) * 100"
          icon={SlidersHorizontal}
          color="var(--accent-cyan)"
        />
        <MetricCard
          label="Identified Gaps"
          value={summary.uncovered_gaps || 0}
          subtext="Exposed attack vectors"
          icon={AlertCircle}
          color="var(--accent-danger)"
        />
      </div>

      {/* Security Tool Toggle Switches */}
      <div style={{ marginBottom: '24px' }}>
        <div style={{ fontSize: '11.5px', fontWeight: '700', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '8px' }}>
          Connected Security Tools & Telemetry Engines
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
          {data?.tools?.map((tool) => {
            const isEnabled = activeTools.includes(tool.tool);
            return (
              <div
                key={tool.tool}
                onClick={() => toggleTool(tool.tool)}
                style={{
                  padding: '12px 14px',
                  borderRadius: '8px',
                  backgroundColor: 'var(--bg-surface)',
                  border: `1px solid ${isEnabled ? 'var(--accent-primary)' : 'var(--border-color)'}`,
                  cursor: 'pointer',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  boxShadow: 'var(--shadow-sm)',
                  transition: 'all 0.15s ease',
                }}
              >
                <div>
                  <div style={{ fontWeight: '700', fontSize: '13px', color: 'var(--text-main)' }}>
                    {tool.tool}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    {tool.techniques_covered} Techniques • {tool.active_rules} Rules
                  </div>
                  <div style={{ marginTop: '4px' }}>
                    <span className="badge badge-demo">{tool.status}</span>
                  </div>
                </div>
                <div style={{ color: isEnabled ? 'var(--accent-primary)' : 'var(--text-muted)' }}>
                  {isEnabled ? <ToggleRight size={26} /> : <ToggleLeft size={26} />}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Columnar ATT&CK Matrix */}
      <div className="card" style={{ padding: '16px' }}>
        <div className="card-title">
          <span>MITRE ATT&CK Columnar Matrix</span>
          <span style={{ fontSize: '12px', fontWeight: '500', color: 'var(--text-muted)' }}>
            Green = Covered • White/Neutral = Exposed (Gap)
          </span>
        </div>

        {loading && !data ? (
          <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-muted)' }}>
            Compiling ATT&CK matrix columns...
          </div>
        ) : (
          <div style={{ display: 'flex', gap: '14px', overflowX: 'auto', paddingBottom: '16px' }}>
            {data?.columns?.map((col) => (
              <div
                key={col.tactic_name}
                style={{
                  width: '240px',
                  minWidth: '240px',
                  backgroundColor: 'var(--bg-surface-alt)',
                  borderRadius: '8px',
                  border: '1px solid var(--border-color)',
                  display: 'flex',
                  flexDirection: 'column',
                  maxHeight: '680px',
                }}
              >
                {/* Column Header */}
                <div
                  style={{
                    padding: '12px',
                    borderBottom: '1px solid var(--border-color)',
                    backgroundColor: 'var(--bg-surface)',
                    borderTopLeftRadius: '8px',
                    borderTopRightRadius: '8px',
                  }}
                >
                  <div style={{ fontWeight: '700', fontSize: '13px', color: 'var(--text-main)' }}>
                    {col.tactic_name}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    {col.covered_count} covered / {col.total_techniques} total
                  </div>
                </div>

                {/* Column Items */}
                <div style={{ padding: '8px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {col.techniques?.map((tech) => (
                    <div
                      key={tech.id}
                      onClick={() => setSelectedTechnique(tech.technique_id)}
                      style={{
                        padding: '10px',
                        borderRadius: '6px',
                        cursor: 'pointer',
                        backgroundColor: tech.is_covered ? 'var(--status-covered-bg)' : 'var(--bg-surface)',
                        border: `1px solid ${tech.is_covered ? 'var(--status-covered-border)' : 'var(--border-color)'}`,
                        boxShadow: 'var(--shadow-sm)',
                        transition: 'transform 0.1s ease',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2px' }}>
                        <span style={{ fontSize: '11.5px', fontWeight: '800', color: tech.is_covered ? 'var(--status-covered-text)' : 'var(--text-main)' }}>
                          {tech.technique_id}
                        </span>
                        {tech.is_covered ? (
                          <span className="badge badge-covered" style={{ fontSize: '10px' }}>
                            {tech.active_rules_count} Rules
                          </span>
                        ) : (
                          <span className="badge badge-exposed" style={{ fontSize: '10px' }}>
                            Gap
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: '12px', fontWeight: '500', color: 'var(--text-main)', lineHeight: '1.3' }}>
                        {tech.name}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Technique Detail Drawer */}
      {selectedTechnique && (
        <TechniqueDrawer
          techniqueId={selectedTechnique}
          onClose={() => setSelectedTechnique(null)}
        />
      )}
    </div>
  );
};

export default CoverageMatrix;
