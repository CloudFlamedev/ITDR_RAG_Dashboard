import React, { useEffect, useState } from 'react';
import { useFilters } from '../context/FilterContext';
import apiClient from '../api/client';
import ResilienceQuadrant from '../components/ResilienceQuadrant';
import MetricCard from '../components/MetricCard';
import { Workflow, ShieldCheck, AlertCircle, FileCheck, Layers } from 'lucide-react';

export const ThreatScenarios = () => {
  const { getFilterParams } = useFilters();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedScenario, setSelectedScenario] = useState(null);

  const filterParams = getFilterParams();

  useEffect(() => {
    setLoading(true);
    apiClient
      .getThreatScenarios(filterParams)
      .then((res) => {
        setData(res);
        if (res.scenarios?.length) setSelectedScenario(res.scenarios[0]);
      })
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, [filterParams.client_restriction, filterParams.itdr_scope]);

  const breakdown = data?.status_breakdown || {};

  return (
    <div className="page-body">
      {/* Header */}
      <div style={{ marginBottom: '20px' }}>
        <h1 style={{ fontSize: '22px', fontWeight: '800', color: 'var(--text-main)' }}>
          Identity Threat Scenarios
        </h1>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '2px' }}>
          Multi-stage attack scenario evaluations mapped onto the 2D Resilience Quadrant (Detection % vs Mitigation %).
        </p>
      </div>

      {/* KPI Cards */}
      <div className="grid-cols-4">
        <MetricCard
          label="Total Scenarios"
          value={data?.total_scenarios || 0}
          subtext="Evaluated multi-stage attack chains"
          icon={Workflow}
          color="var(--accent-primary)"
        />
        <MetricCard
          label="Resilient"
          value={breakdown['Resilient'] || 0}
          subtext="High Detection & High Mitigation"
          icon={ShieldCheck}
          color="var(--accent-teal)"
        />
        <MetricCard
          label="Paper Tiger"
          value={breakdown['Paper Tiger'] || 0}
          subtext="High Detection & Low Mitigation"
          icon={FileCheck}
          color="var(--accent-warning)"
        />
        <MetricCard
          label="High Risk / Silent Well"
          value={(breakdown['High Risk'] || 0) + (breakdown['Silent Well'] || 0)}
          subtext="Defensive posture remediation needed"
          icon={AlertCircle}
          color="var(--accent-danger)"
        />
      </div>

      {/* 2-Column Layout: Left = Quadrant, Right = Scrollable List */}
      <div className="grid-cols-2">
        {/* Left: Resilience Quadrant */}
        <div className="card">
          <div className="card-title">
            <span>Resilience Quadrant (2D Scatter Plot)</span>
            <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>Click point to inspect</span>
          </div>
          <ResilienceQuadrant
            points={data?.scenarios || []}
            onSelectScenario={(s) => setSelectedScenario(s)}
          />
          <div style={{ marginTop: '16px', fontSize: '12px', color: 'var(--text-muted)', lineHeight: '1.5' }}>
            Positioning formula: Horizontal X-axis represents control mitigation percentage; Vertical Y-axis represents sensor detection percentage.
          </div>
        </div>

        {/* Right: Resilient Scenarios Status List */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="card-title">
            <span>Resilient Scenarios Status List</span>
            <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
              {data?.scenarios?.length || 0} Scenarios
            </span>
          </div>

          <div style={{ flex: 1, overflowY: 'auto', maxHeight: '420px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {data?.scenarios?.map((scen) => {
              const isSelected = selectedScenario?.id === scen.id;
              return (
                <div
                  key={scen.id}
                  onClick={() => setSelectedScenario(scen)}
                  style={{
                    padding: '12px 14px',
                    borderRadius: '8px',
                    backgroundColor: isSelected ? 'var(--bg-surface-alt)' : 'var(--bg-surface)',
                    border: `1.5px solid ${isSelected ? 'var(--accent-primary)' : 'var(--border-color)'}`,
                    cursor: 'pointer',
                    boxShadow: 'var(--shadow-sm)',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '4px' }}>
                    <div style={{ fontWeight: '700', fontSize: '13.5px', color: 'var(--text-main)' }}>
                      {scen.name}
                    </div>
                    <span
                      className={`badge ${
                        scen.status === 'Resilient'
                          ? 'badge-covered'
                          : 'badge-exposed'
                      }`}
                    >
                      {scen.status}
                    </span>
                  </div>

                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px' }}>
                    {scen.description}
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11.5px' }}>
                    <span style={{ color: 'var(--text-muted)' }}>
                      Source: <strong>{scen.source}</strong>
                    </span>
                    <span style={{ color: 'var(--text-main)', fontWeight: '600' }}>
                      Det: {scen.detection_pct}% • Mit: {scen.mitigation_pct}%
                    </span>
                  </div>

                  {scen.attack_chain_ttps?.length > 0 && (
                    <div style={{ marginTop: '8px', display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                      {scen.attack_chain_ttps.map((ttp) => (
                        <span key={ttp} className="badge badge-demo" style={{ fontSize: '10px' }}>
                          {ttp}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatScenarios;
