import React, { useEffect, useState } from 'react';
import apiClient from '../api/client';
import { X, ExternalLink, ShieldCheck, AlertTriangle, Layers, BookOpen } from 'lucide-react';

export const TechniqueDrawer = ({ techniqueId, onClose }) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!techniqueId) return;
    setLoading(true);
    apiClient
      .getTtpDetail(techniqueId)
      .then((res) => setData(res))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, [techniqueId]);

  if (!techniqueId) return null;

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <div className="drawer-panel" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="drawer-header">
          <div>
            <div style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              MITRE ATT&CK Technique Detail
            </div>
            <div style={{ fontSize: '18px', fontWeight: '800', color: 'var(--text-main)' }}>
              {data?.technique_id || techniqueId} {data?.name ? `– ${data.name}` : ''}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Body */}
        <div className="drawer-body">
          {loading ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Loading technique telemetry...
            </div>
          ) : data ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* Coverage Status Banner */}
              <div
                style={{
                  padding: '12px 16px',
                  borderRadius: '8px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  backgroundColor: data.is_covered ? 'var(--status-covered-bg)' : 'var(--status-exposed-bg)',
                  border: `1px solid ${data.is_covered ? 'var(--status-covered-border)' : 'var(--status-exposed-border)'}`,
                  color: data.is_covered ? 'var(--status-covered-text)' : 'var(--status-exposed-text)',
                }}
              >
                {data.is_covered ? <ShieldCheck size={20} /> : <AlertTriangle size={20} />}
                <div>
                  <div style={{ fontWeight: '700', fontSize: '13px' }}>
                    {data.is_covered ? 'Active Detection Coverage Verified' : 'Exposed Technique (Coverage Gap)'}
                  </div>
                  <div style={{ fontSize: '12px', opacity: 0.9 }}>
                    {data.coverage_rationale}
                  </div>
                </div>
              </div>

              {/* Tactic & Platform Chips */}
              <div>
                <div style={{ fontSize: '11px', fontWeight: '700', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '8px' }}>
                  Tactics & Platforms
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                  {data.tactics?.map((t) => (
                    <span key={t} className="badge badge-demo">
                      {t}
                    </span>
                  ))}
                  {data.platforms?.map((p) => (
                    <span key={p} className="badge" style={{ backgroundColor: 'var(--bg-surface-alt)', border: '1px solid var(--border-color)', color: 'var(--text-main)' }}>
                      {p}
                    </span>
                  ))}
                  {data.url && (
                    <a
                      href={data.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="badge"
                      style={{ backgroundColor: 'var(--accent-primary)', color: 'white', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '4px' }}
                    >
                      MITRE ATT&CK <ExternalLink size={10} />
                    </a>
                  )}
                </div>
              </div>

              {/* Description */}
              <div>
                <div style={{ fontSize: '11px', fontWeight: '700', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '8px' }}>
                  Technique Description
                </div>
                <p style={{ fontSize: '13px', color: 'var(--text-main)', lineHeight: '1.6', backgroundColor: 'var(--bg-surface-alt)', padding: '12px', borderRadius: '6px' }}>
                  {data.description || 'No description available.'}
                </p>
              </div>

              {/* Mapped Detection Rules */}
              <div>
                <div style={{ fontSize: '11px', fontWeight: '700', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <ShieldCheck size={14} /> Mapped Security Rules & Controls ({data.mapped_rules?.length || 0})
                </div>
                {data.mapped_rules?.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {data.mapped_rules.map((rule) => (
                      <div
                        key={rule.rule_id}
                        style={{
                          padding: '10px 12px',
                          borderRadius: '6px',
                          border: '1px solid var(--border-color)',
                          backgroundColor: 'var(--bg-surface)',
                          fontSize: '12.5px',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                          <span style={{ fontWeight: '700', color: 'var(--text-main)' }}>{rule.name}</span>
                          <span className="badge badge-demo">{rule.tool}</span>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          Rule ID: {rule.rule_id} • Status: {rule.validation_status} ({rule.coverage_level})
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: '12.5px', color: 'var(--accent-danger)', fontStyle: 'italic', padding: '10px', backgroundColor: 'var(--status-exposed-bg)', borderRadius: '6px' }}>
                    No detection rules currently deployed for this technique. Recommend authoring custom SIEM/EDR rule.
                  </div>
                )}
              </div>

              {/* MITRE D3FEND Countermeasures */}
              <div>
                <div style={{ fontSize: '11px', fontWeight: '700', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Layers size={14} /> MITRE D3FEND Defensive Techniques ({data.mapped_defences?.length || 0})
                </div>
                {data.mapped_defences?.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {data.mapped_defences.map((def) => (
                      <div
                        key={def.d3fend_id}
                        style={{
                          padding: '10px 12px',
                          borderRadius: '6px',
                          border: '1px solid var(--border-color)',
                          backgroundColor: 'var(--bg-surface-alt)',
                          fontSize: '12px',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2px' }}>
                          <strong style={{ color: 'var(--accent-primary)' }}>{def.d3fend_id}: {def.name}</strong>
                          <span style={{ fontSize: '10.5px', textTransform: 'uppercase', fontWeight: '600', color: 'var(--text-muted)' }}>{def.relationship}</span>
                        </div>
                        <div style={{ color: 'var(--text-muted)', fontSize: '11.5px', marginTop: '4px' }}>
                          {def.definition || 'Official defensive technique.'}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                    No direct D3FEND mitigation mapped in official ontology.
                  </div>
                )}
              </div>

              {/* Procedure Examples */}
              {data.procedures?.length > 0 && (
                <div>
                  <div style={{ fontSize: '11px', fontWeight: '700', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <BookOpen size={14} /> In-the-Wild Procedure Examples
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {data.procedures.map((p, idx) => (
                      <div
                        key={idx}
                        style={{
                          padding: '8px 10px',
                          borderRadius: '4px',
                          backgroundColor: 'var(--bg-surface-alt)',
                          fontSize: '11.5px',
                          color: 'var(--text-muted)',
                        }}
                      >
                        <strong style={{ color: 'var(--text-main)' }}>{p.source}:</strong> {p.description}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div>Technique details unavailable.</div>
          )}
        </div>
      </div>
    </div>
  );
};

export default TechniqueDrawer;
