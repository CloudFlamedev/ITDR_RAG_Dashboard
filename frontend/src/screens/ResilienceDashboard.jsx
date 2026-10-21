import React, { useEffect, useState } from 'react';
import { useFilters } from '../context/FilterContext';
import apiClient from '../api/client';
import MetricCard from '../components/MetricCard';
import CoverageRing from '../components/CoverageRing';
import TacticExposureChart from '../components/TacticExposureChart';
import ResilienceQuadrant from '../components/ResilienceQuadrant';
import TechniqueDrawer from '../components/TechniqueDrawer';
import { Shield, AlertOctagon, CheckCircle2, Sliders, ExternalLink } from 'lucide-react';

export const ResilienceDashboard = () => {
  const { getFilterParams } = useFilters();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedTechnique, setSelectedTechnique] = useState(null);

  const filterParams = getFilterParams();

  useEffect(() => {
    setLoading(true);
    apiClient
      .getIdentityResilience(filterParams)
      .then((res) => setData(res))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, [filterParams.client_restriction, filterParams.itdr_scope, filterParams.view_mode]);

  if (loading && !data) {
    return (
      <div className="page-body" style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>
        Loading Identity Resilience Posture telemetry...
      </div>
    );
  }

  const summary = data?.summary || {};

  return (
    <div className="page-body">
      {/* Page Header */}
      <div style={{ marginBottom: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 style={{ fontSize: '22px', fontWeight: '800', color: 'var(--text-main)' }}>
            Identity Resilience Dashboard
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Continuous security visibility, MITRE defensive coverage, and critical identity attack blind spots.
          </p>
        </div>
        {summary.is_demo && <span className="badge badge-demo">DEMO DATA ACTIVE</span>}
      </div>

      {/* Top 4 KPI Cards */}
      <div className="grid-cols-4">
        <MetricCard
          label="Coverage Score"
          value={`${summary.coverage_score || 0}%`}
          subtext={`${summary.covered_techniques_count || 0} of ${summary.total_in_scope_techniques || 0} techniques`}
          icon={Shield}
          color="var(--accent-teal)"
        />
        <MetricCard
          label="Active Detection Rules"
          value={summary.active_rules_deployed || 0}
          subtext="CrowdStrike, MDI, Okta, Wiz, In-House"
          icon={CheckCircle2}
          color="var(--accent-primary)"
        />
        <MetricCard
          label="Critical Blind Spots"
          value={summary.exposed_techniques_count || 0}
          subtext="Exposed techniques with 0 active rules"
          icon={AlertOctagon}
          color="var(--accent-danger)"
        />
        <MetricCard
          label="In-Scope Techniques"
          value={summary.total_in_scope_techniques || 0}
          subtext="Filtered by current identity boundaries"
          icon={Sliders}
          color="var(--accent-cyan)"
        />
      </div>

      {/* Main Grid: Coverage Ring & Tactic Exposure Bars */}
      <div className="grid-cols-2">
        {/* Coverage Score Ring */}
        <div className="card">
          <div className="card-title">
            <span>Identity Security Coverage Ring</span>
            <span style={{ fontSize: '12px', fontWeight: '500', color: 'var(--text-muted)' }}>
              (Covered / In-Scope) * 100
            </span>
          </div>
          <div style={{ padding: '20px 0' }}>
            <CoverageRing percentage={summary.coverage_score || 0} />
          </div>
          <div style={{ textAlign: 'center', fontSize: '12px', color: 'var(--text-muted)' }}>
            Protection evaluated against enabled detection rules and active control validation checks.
          </div>
        </div>

        {/* ATT&CK Tactic Exposure Bars */}
        <div className="card">
          <div className="card-title">
            <span>MITRE Tactic Exposure</span>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Covered vs Exposed Counts</span>
          </div>
          <TacticExposureChart tacticBars={data?.tactic_bars || []} />
        </div>
      </div>

      {/* Lower Grid: Resilience Quadrant & Critical Blind Spots */}
      <div className="grid-cols-2">
        {/* Resilience Quadrant */}
        <div className="card">
          <div className="card-title">
            <span>Resilience Quadrant</span>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Mitigation % vs Detection %</span>
          </div>
          <ResilienceQuadrant points={data?.quadrant_points || []} />
        </div>

        {/* Critical Blind Spots */}
        <div className="card">
          <div className="card-title">
            <span>Critical Blind Spots</span>
            <span style={{ fontSize: '11px', color: 'var(--accent-danger)', fontWeight: '600' }}>
              Priority Remediation Required
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {data?.critical_blind_spots?.slice(0, 5).map((spot) => (
              <div
                key={spot.technique_id}
                onClick={() => setSelectedTechnique(spot.technique_id)}
                style={{
                  padding: '10px 12px',
                  borderRadius: '6px',
                  backgroundColor: 'var(--bg-surface-alt)',
                  border: '1px solid var(--border-color)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  cursor: 'pointer',
                  transition: 'background-color 0.15s ease',
                }}
              >
                <div>
                  <div style={{ fontWeight: '700', fontSize: '13px', color: 'var(--text-main)' }}>
                    {spot.technique_id} – {spot.name}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    {spot.tactics?.join(', ') || 'Identity Attack Surface'}
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span className="badge badge-exposed">Exposed</span>
                  <ExternalLink size={14} color="var(--text-muted)" />
                </div>
              </div>
            ))}
          </div>
        </div>
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

export default ResilienceDashboard;
