import React, { useEffect, useState } from 'react';
import { useFilters } from '../context/FilterContext';
import apiClient from '../api/client';
import MetricCard from '../components/MetricCard';
import TechniqueDrawer from '../components/TechniqueDrawer';
import { Radio, ShieldCheck, AlertTriangle } from 'lucide-react';

export const ThreatExposure = () => {
  const { getFilterParams } = useFilters();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedTechnique, setSelectedTechnique] = useState(null);

  const filterParams = getFilterParams();

  useEffect(() => {
    setLoading(true);
    apiClient
      .getThreatExposure(filterParams)
      .then((res) => setData(res))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, [filterParams.client_restriction, filterParams.itdr_scope]);

  const summary = data?.summary || {};

  return (
    <div className="page-body">
      {/* Header */}
      <div style={{ marginBottom: '20px' }}>
        <h1 style={{ fontSize: '22px', fontWeight: '800', color: 'var(--text-main)' }}>
          Identity Threat Exposure
        </h1>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '2px' }}>
          Sighted adversarial TTPs from processed threat intelligence feeds evaluated against defensive coverage.
        </p>
      </div>

      {/* Top KPI Banner */}
      <div className="grid-cols-4">
        <MetricCard
          label="MITRE TTPs Sighted"
          value={summary.total_ttps_sighted || 0}
          subtext="Observed in active CTI bulletins"
          icon={Radio}
          color="var(--accent-primary)"
        />
        <MetricCard
          label="Sighted with Coverage"
          value={summary.sighted_with_coverage || 0}
          subtext="Covered by active detection rules"
          icon={ShieldCheck}
          color="var(--accent-teal)"
        />
        <MetricCard
          label="Sighted without Coverage"
          value={summary.sighted_without_coverage || 0}
          subtext="Critical unmanaged attack gaps"
          icon={AlertTriangle}
          color="var(--accent-danger)"
        />
        <MetricCard
          label="Exposure Ratio"
          value={`${summary.total_ttps_sighted ? Math.round((summary.sighted_without_coverage / summary.total_ttps_sighted) * 100) : 0}%`}
          subtext="(Exposed Sighted / Total Sighted) * 100"
          icon={AlertTriangle}
          color="var(--accent-warning)"
        />
      </div>

      {/* Attack Phase Columns */}
      <div className="card">
        <div className="card-title">
          <span>Sighted TTPs Grouped by Attack Phase</span>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Green Border = Covered • Red Border = Exposed
          </span>
        </div>

        {loading ? (
          <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-muted)' }}>
            Evaluating sighted TTPs...
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '16px' }}>
            {data?.phase_columns?.map((phase) => (
              <div
                key={phase.tactic_name}
                style={{
                  backgroundColor: 'var(--bg-surface-alt)',
                  borderRadius: '8px',
                  border: '1px solid var(--border-color)',
                  padding: '12px',
                }}
              >
                <div style={{ fontWeight: '700', fontSize: '13px', color: 'var(--text-main)', marginBottom: '10px' }}>
                  {phase.tactic_name} ({phase.techniques?.length || 0})
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {phase.techniques?.map((tech) => (
                    <div
                      key={tech.technique_id}
                      onClick={() => setSelectedTechnique(tech.technique_id)}
                      style={{
                        padding: '10px 12px',
                        borderRadius: '6px',
                        backgroundColor: 'var(--bg-surface)',
                        border: `1.5px solid ${tech.is_covered ? 'var(--accent-teal)' : 'var(--accent-danger)'}`,
                        cursor: 'pointer',
                        boxShadow: 'var(--shadow-sm)',
                        transition: 'transform 0.1s ease',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2px' }}>
                        <span style={{ fontWeight: '800', fontSize: '12px', color: 'var(--text-main)' }}>
                          {tech.technique_id}
                        </span>
                        <span className="badge" style={{ backgroundColor: 'var(--bg-surface-alt)', border: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '10.5px' }}>
                          {tech.sightings_count} Sighted
                        </span>
                      </div>
                      <div style={{ fontSize: '12px', fontWeight: '500', color: 'var(--text-main)', lineHeight: '1.3' }}>
                        {tech.name}
                      </div>
                      <div style={{ marginTop: '6px' }}>
                        <span className={`badge ${tech.is_covered ? 'badge-covered' : 'badge-exposed'}`}>
                          {tech.is_covered ? 'Covered' : 'Exposed Gap'}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Technique Drawer */}
      {selectedTechnique && (
        <TechniqueDrawer
          techniqueId={selectedTechnique}
          onClose={() => setSelectedTechnique(null)}
        />
      )}
    </div>
  );
};

export default ThreatExposure;
