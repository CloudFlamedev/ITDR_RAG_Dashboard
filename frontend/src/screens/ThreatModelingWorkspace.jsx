import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useFilters } from '../context/FilterContext';
import apiClient from '../api/client';
import TraceStepper from '../components/TraceStepper';
import {
  Terminal,
  Cpu,
  Sparkles,
  Play,
  ArrowRight,
  ArrowLeft,
  CheckCircle2,
  AlertTriangle,
  Download,
  BookOpen,
  Shield,
  Layers,
  FileCode,
} from 'lucide-react';

export const ThreatModelingWorkspace = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { viewMode, clientRestriction, itdrScope, systemStatus } = useFilters();

  // 3-Step Journey: 1 = Input Advisory, 2 = Model Options, 3 = Telemetry & Report
  const [activeStep, setActiveStep] = useState(1);

  // Step 1: Input
  const [advisoryText, setAdvisoryText] = useState(
    location.state?.advisoryText ||
    'Adversaries used T1078.004 cloud credentials and dumped LSASS memory on DC-PRIMARY-01 to bypass authentication'
  );
  const [samples, setSamples] = useState([]);
  const [selectedSampleId, setSelectedSampleId] = useState(null);

  // Step 2: Options
  const [includeD3fend, setIncludeD3fend] = useState(true);
  const [maxCandidates, setMaxCandidates] = useState(8);

  // Step 3: Execution & Output
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [analysisError, setAnalysisError] = useState(null);

  // Load samples
  useEffect(() => {
    apiClient.getThreatSamples().then((data) => setSamples(data)).catch((err) => console.error(err));
  }, []);

  const handleSelectSample = (sample) => {
    setSelectedSampleId(sample.id);
    setAdvisoryText(sample.text);
  };

  const handleStartAnalysis = async () => {
    setActiveStep(3);
    setAnalyzing(true);
    setAnalysisError(null);
    setAnalysisResult(null);

    try {
      const res = await apiClient.analyzeThreat({
        advisory_text: advisoryText,
        sample_id: selectedSampleId,
        client_restriction: clientRestriction,
        itdr_scope: itdrScope,
        view_mode: viewMode,
        include_d3fend: includeD3fend,
        max_technique_candidates: maxCandidates,
      });
      setAnalysisResult(res);
    } catch (err) {
      console.error('Analysis error:', err);
      setAnalysisError(err.response?.data?.detail || err.message || 'Threat modeling pipeline failed.');
    } finally {
      setAnalyzing(false);
    }
  };

  const handleExportJSON = () => {
    if (!analysisResult) return;
    const blob = new Blob([JSON.stringify(analysisResult, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${analysisResult.report_id || 'threat-report'}.json`;
    a.click();
  };

  const handleExportMarkdown = () => {
    if (!analysisResult?.report) return;
    const rep = analysisResult.report;
    const md = `# ${rep.report_title}
**Report ID**: ${analysisResult.report_id}
**Severity**: ${rep.severity}
**Status**: ${analysisResult.status}

## Executive Summary
${rep.executive_summary}

## Incident Overview
${rep.incident_overview}

## Candidate MITRE ATT&CK Techniques
${rep.technique_candidates?.map(c => `- **${c.technique_id}: ${c.name}** (Confidence: ${c.relevance_score})\n  *Rationale*: ${c.rationale}`).join('\n\n')}

## Mapped MITRE D3FEND Countermeasures
${rep.defensive_techniques?.map(d => `- **${d.d3fend_id}: ${d.name}** (${d.relationship_type})\n  *Provenance*: ${d.provenance}\n  *Action*: ${d.rationale}`).join('\n\n')}

## Coverage Assessment & Gaps
${rep.coverage_assessment?.map(cov => `- **${cov.technique_id}**: Status ${cov.status.toUpperCase()} (${cov.active_rules_count} rules deployed across ${cov.mapped_tools?.join(', ') || 'None'})`).join('\n')}

## Recommended Actions
${rep.recommended_actions?.map(a => `- [${a.priority}] **${a.category}**: ${a.action} (${a.rationale})`).join('\n')}

## Grounded Citations
${analysisResult.citations?.map(cit => `- [${cit.external_id}] (${cit.citation_role}) "${cit.excerpt}" - Source: ${cit.source_id}`).join('\n')}
`;

    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${analysisResult.report_id || 'threat-report'}.md`;
    a.click();
  };

  const rep = analysisResult?.report;

  return (
    <div className="page-body">
      {/* Workspace Header */}
      <div style={{ marginBottom: '20px' }}>
        <h1 style={{ fontSize: '22px', fontWeight: '800', color: 'var(--text-main)' }}>
          Threat Modeling Workspace
        </h1>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '2px' }}>
          Explainable, stateful RAG pipeline with Grok, Hugging Face Embeddings, and MITRE ATT&CK/D3FEND knowledge.
        </p>
      </div>

      {/* 3-Step Journey Stepper Banner */}
      <div
        className="card"
        style={{
          marginBottom: '24px',
          padding: '14px 20px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          backgroundColor: 'var(--bg-surface)',
        }}
      >
        {[
          { num: 1, title: 'Input Threat Intelligence', desc: 'Paste advisory or pick sample' },
          { num: 2, title: 'Select Model & Options', desc: 'Configure Grok & RAG scope' },
          { num: 3, title: 'Telemetry, Trace & Report', desc: 'LangGraph trace & validated brief' },
        ].map((s) => {
          const isActive = activeStep === s.num;
          const isDone = activeStep > s.num;
          return (
            <div
              key={s.num}
              onClick={() => !analyzing && setActiveStep(s.num)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                cursor: analyzing ? 'default' : 'pointer',
                opacity: isActive || isDone ? 1 : 0.6,
              }}
            >
              <div
                style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontWeight: '700',
                  fontSize: '13px',
                  backgroundColor: isDone
                    ? 'var(--accent-teal)'
                    : isActive
                    ? 'var(--accent-primary)'
                    : 'var(--bg-surface-alt)',
                  color: isDone || isActive ? 'white' : 'var(--text-muted)',
                  border: isDone || isActive ? 'none' : '1px solid var(--border-color)',
                }}
              >
                {isDone ? <CheckCircle2 size={16} /> : s.num}
              </div>
              <div>
                <div style={{ fontSize: '13px', fontWeight: '700', color: 'var(--text-main)' }}>
                  Step {s.num}: {s.title}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{s.desc}</div>
              </div>
            </div>
          );
        })}
      </div>

      {/* STEP 1: Input Threat Intelligence */}
      {activeStep === 1 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Sample Selectors */}
          <div className="card">
            <div className="card-title">
              <span>Quick-Load Labelled Sample Advisories</span>
              <span className="badge badge-demo">DEMO SAMPLES</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '10px' }}>
              {samples.map((s) => (
                <button
                  key={s.id}
                  type="button"
                  onClick={() => handleSelectSample(s)}
                  style={{
                    padding: '10px 12px',
                    borderRadius: '6px',
                    textAlign: 'left',
                    cursor: 'pointer',
                    backgroundColor: selectedSampleId === s.id ? 'var(--bg-surface-alt)' : 'var(--bg-surface)',
                    border: `1.5px solid ${selectedSampleId === s.id ? 'var(--accent-primary)' : 'var(--border-color)'}`,
                    boxShadow: 'var(--shadow-sm)',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ fontWeight: '700', fontSize: '12.5px', color: 'var(--text-main)', marginBottom: '3px' }}>
                    {s.title}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--accent-primary)' }}>Source: {s.source}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Narrative Input Box */}
          <div className="card">
            <div className="card-title">
              <span>Security Advisory / Incident Narrative Input</span>
              <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>Paste raw text below</span>
            </div>
            <textarea
              rows={8}
              value={advisoryText}
              onChange={(e) => {
                setAdvisoryText(e.target.value);
                setSelectedSampleId(null);
              }}
              placeholder="Paste security advisory, SIEM detection alert, log excerpt, or attack narrative..."
              style={{
                width: '100%',
                padding: '14px',
                borderRadius: '8px',
                border: '1px solid var(--border-color)',
                backgroundColor: 'var(--bg-surface-alt)',
                color: 'var(--text-main)',
                fontSize: '13.5px',
                fontFamily: 'var(--font-mono)',
                lineHeight: '1.6',
                resize: 'vertical',
              }}
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '16px' }}>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                {advisoryText.length} characters • {advisoryText.split(/\s+/).filter(Boolean).length} words
              </span>
              <button
                className="btn btn-primary"
                onClick={() => setActiveStep(2)}
                disabled={!advisoryText.trim()}
              >
                <span>Next: Select Model & Options</span>
                <ArrowRight size={14} />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* STEP 2: Select Model & Analysis Options */}
      {activeStep === 2 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div className="grid-cols-2">
            {/* LLM & Embedding Status */}
            <div className="card">
              <div className="card-title">
                <span>Configured AI Subsystems</span>
                <span className="badge badge-demo">BACKEND PROTECTED</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div style={{ padding: '12px', borderRadius: '6px', backgroundColor: 'var(--bg-surface-alt)', border: '1px solid var(--border-color)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: '700', fontSize: '13px' }}>
                      <Sparkles size={16} color="var(--accent-primary)" />
                      <span>xAI Grok Chat LLM</span>
                    </div>
                    <span className="badge badge-covered">
                      {systemStatus?.subsystems?.xai_grok?.status || 'Grounded Engine'}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    Model: <strong>{systemStatus?.subsystems?.xai_grok?.model || 'grok-4.7'}</strong> • Endpoint: {systemStatus?.subsystems?.xai_grok?.base_url || 'https://api.x.ai/v1'}
                  </div>
                </div>

                <div style={{ padding: '12px', borderRadius: '6px', backgroundColor: 'var(--bg-surface-alt)', border: '1px solid var(--border-color)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: '700', fontSize: '13px' }}>
                      <Cpu size={16} color="var(--accent-teal)" />
                      <span>Hugging Face Embedding Provider</span>
                    </div>
                    <span className="badge badge-covered">
                      {systemStatus?.subsystems?.huggingface?.status || 'Online'}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    Model: <strong>{systemStatus?.subsystems?.huggingface?.model || 'BAAI/bge-small-en-v1.5'}</strong> • Dimensions: 384
                  </div>
                </div>

                <div style={{ padding: '12px', borderRadius: '6px', backgroundColor: 'var(--bg-surface-alt)', border: '1px solid var(--border-color)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: '700', fontSize: '13px' }}>
                      <Layers size={16} color="var(--accent-cyan)" />
                      <span>Neon PostgreSQL + pgvector</span>
                    </div>
                    <span className="badge badge-covered">
                      {systemStatus?.subsystems?.database?.status || 'Online'}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    Storage: 1,679+ semantic vectors • Distance: Cosine Similarity
                  </div>
                </div>
              </div>
            </div>

            {/* Analysis Options */}
            <div className="card">
              <div className="card-title">
                <span>RAG Retrieval & Evaluation Options</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: '600', marginBottom: '4px' }}>
                    Max Technique Candidates
                  </label>
                  <input
                    type="range"
                    min="3"
                    max="15"
                    value={maxCandidates}
                    onChange={(e) => setMaxCandidates(Number(e.target.value))}
                    style={{ width: '100%' }}
                  />
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-muted)' }}>
                    <span>Top 3</span>
                    <span>Selected: <strong>{maxCandidates} candidates</strong></span>
                    <span>Top 15</span>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px', borderRadius: '6px', backgroundColor: 'var(--bg-surface-alt)', border: '1px solid var(--border-color)' }}>
                  <div>
                    <div style={{ fontWeight: '700', fontSize: '13px' }}>Include MITRE D3FEND Countermeasures</div>
                    <div style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                      Cross-reference defensive techniques and authentic mapping provenance
                    </div>
                  </div>
                  <input
                    type="checkbox"
                    checked={includeD3fend}
                    onChange={(e) => setIncludeD3fend(e.target.checked)}
                    style={{ width: '18px', height: '18px', cursor: 'pointer' }}
                  />
                </div>

                <div style={{ padding: '10px 12px', borderRadius: '6px', backgroundColor: 'var(--bg-surface-alt)', fontSize: '12px', color: 'var(--text-muted)' }}>
                  Active Global Scope: <strong>{itdrScope}</strong> • Tenancy: <strong>{clientRestriction}</strong>
                </div>
              </div>
            </div>
          </div>

          {/* Action Row */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <button className="btn btn-secondary" onClick={() => setActiveStep(1)}>
              <ArrowLeft size={14} />
              <span>Back to Input</span>
            </button>
            <button className="btn btn-primary" onClick={handleStartAnalysis}>
              <Play size={14} />
              <span>Launch Threat Analysis Workflow</span>
            </button>
          </div>
        </div>
      )}

      {/* STEP 3: Telemetry, Trace & Report */}
      {activeStep === 3 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Running State Spinner */}
          {analyzing && (
            <div className="card" style={{ padding: '40px', textAlign: 'center' }}>
              <div style={{ fontSize: '16px', fontWeight: '700', color: 'var(--accent-primary)', marginBottom: '8px' }}>
                Executing 11-Node LangGraph State Machine...
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                Validating input → Vector search → D3FEND resolution → Coverage audit → Grok structured report → Citation verification
              </div>
            </div>
          )}

          {/* Error Message */}
          {analysisError && (
            <div className="card" style={{ backgroundColor: 'var(--status-exposed-bg)', border: '1px solid var(--status-exposed-border)', color: 'var(--status-exposed-text)' }}>
              <div style={{ fontWeight: '700', fontSize: '14px', marginBottom: '4px' }}>Analysis Encountered Error</div>
              <div style={{ fontSize: '13px' }}>{analysisError}</div>
              <button className="btn btn-secondary" style={{ marginTop: '12px' }} onClick={() => setActiveStep(2)}>
                Modify Options & Retry
              </button>
            </div>
          )}

          {/* Success Report */}
          {analysisResult && (
            <>
              {/* Observable Trace Stepper */}
              <div className="card">
                <TraceStepper traceSteps={analysisResult.trace_steps || []} />
              </div>

              {/* Executive Brief Header Card */}
              <div className="card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px', marginBottom: '14px' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <span className="badge badge-demo">REPORT ID: {analysisResult.report_id}</span>
                      <span className={`badge ${rep?.severity === 'Critical' || rep?.severity === 'High' ? 'badge-exposed' : 'badge-covered'}`}>
                        SEVERITY: {rep?.severity || 'HIGH'}
                      </span>
                      <span className="badge badge-covered">STATUS: {analysisResult.status}</span>
                    </div>
                    <h2 style={{ fontSize: '20px', fontWeight: '800', color: 'var(--text-main)' }}>
                      {rep?.report_title || 'ITDR Threat Brief'}
                    </h2>
                  </div>

                  {/* Export Buttons */}
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button className="btn btn-secondary" onClick={handleExportJSON} title="Export JSON">
                      <FileCode size={14} />
                      <span>JSON</span>
                    </button>
                    <button className="btn btn-secondary" onClick={handleExportMarkdown} title="Export Markdown">
                      <Download size={14} />
                      <span>Markdown</span>
                    </button>
                  </div>
                </div>

                <div style={{ backgroundColor: 'var(--bg-surface-alt)', padding: '16px', borderRadius: '8px', fontSize: '13.5px', lineHeight: '1.6', color: 'var(--text-main)', marginBottom: '16px' }}>
                  <strong>Executive Summary:</strong> {rep?.executive_summary}
                </div>

                <div style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
                  <strong>Severity Rationale:</strong> {rep?.severity_rationale}
                </div>
              </div>

              {/* Two Column Grid: Candidate Techniques & Defensive Techniques */}
              <div className="grid-cols-2">
                {/* Candidate ATT&CK Techniques */}
                <div className="card">
                  <div className="card-title">
                    <span>Candidate MITRE ATT&CK Techniques ({rep?.technique_candidates?.length || 0})</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {rep?.technique_candidates?.map((c) => (
                      <div
                        key={c.technique_id}
                        style={{
                          padding: '12px',
                          borderRadius: '6px',
                          backgroundColor: 'var(--bg-surface-alt)',
                          border: '1px solid var(--border-color)',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                          <span style={{ fontWeight: '800', fontSize: '13px', color: 'var(--accent-primary)' }}>
                            {c.technique_id}: {c.name}
                          </span>
                          <span className="badge" style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border-color)', fontSize: '11px' }}>
                            Score: {c.relevance_score}
                          </span>
                        </div>
                        <div style={{ fontSize: '12.5px', color: 'var(--text-main)', marginBottom: '6px' }}>
                          {c.rationale}
                        </div>
                        {c.supporting_evidence_ids?.length > 0 && (
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                            Cited Evidence: {c.supporting_evidence_ids.join(', ')}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* MITRE D3FEND Countermeasures */}
                <div className="card">
                  <div className="card-title">
                    <span>MITRE D3FEND Countermeasures ({rep?.defensive_techniques?.length || 0})</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {rep?.defensive_techniques?.map((d) => (
                      <div
                        key={d.d3fend_id}
                        style={{
                          padding: '12px',
                          borderRadius: '6px',
                          backgroundColor: 'var(--bg-surface-alt)',
                          border: '1px solid var(--border-color)',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                          <span style={{ fontWeight: '800', fontSize: '13px', color: 'var(--accent-teal)' }}>
                            {d.d3fend_id}: {d.name}
                          </span>
                          <span className="badge badge-demo">{d.relationship_type}</span>
                        </div>
                        <div style={{ fontSize: '12.5px', color: 'var(--text-main)', marginBottom: '4px' }}>
                          {d.rationale}
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          Provenance: <strong>{d.provenance}</strong>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Coverage Assessment & Recommended Actions */}
              <div className="grid-cols-2">
                {/* Coverage Status */}
                <div className="card">
                  <div className="card-title">
                    <span>Active Detection Rule Coverage Assessment</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {rep?.coverage_assessment?.map((cov) => (
                      <div
                        key={cov.technique_id}
                        style={{
                          padding: '10px 12px',
                          borderRadius: '6px',
                          backgroundColor: cov.status === 'covered' ? 'var(--status-covered-bg)' : 'var(--status-exposed-bg)',
                          border: `1px solid ${cov.status === 'covered' ? 'var(--status-covered-border)' : 'var(--status-exposed-border)'}`,
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                        }}
                      >
                        <div>
                          <div style={{ fontWeight: '700', fontSize: '13px', color: cov.status === 'covered' ? 'var(--status-covered-text)' : 'var(--status-exposed-text)' }}>
                            {cov.technique_id} – {cov.status.toUpperCase()}
                          </div>
                          <div style={{ fontSize: '11.5px', opacity: 0.9 }}>
                            {cov.active_rules_count} active rules ({cov.mapped_tools?.join(', ') || 'No mapped tool'})
                          </div>
                        </div>
                        <span className={`badge ${cov.status === 'covered' ? 'badge-covered' : 'badge-exposed'}`}>
                          {cov.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Recommended Actions */}
                <div className="card">
                  <div className="card-title">
                    <span>Prioritized Defensive Recommendations</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {rep?.recommended_actions?.map((act, idx) => (
                      <div
                        key={idx}
                        style={{
                          padding: '10px 12px',
                          borderRadius: '6px',
                          backgroundColor: 'var(--bg-surface-alt)',
                          border: '1px solid var(--border-color)',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2px' }}>
                          <span style={{ fontWeight: '700', fontSize: '12.5px', color: 'var(--text-main)' }}>
                            [{act.priority}] {act.category}
                          </span>
                        </div>
                        <div style={{ fontSize: '12.5px', color: 'var(--text-main)', marginBottom: '4px' }}>
                          {act.action}
                        </div>
                        <div style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                          {act.rationale}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Citations & Evidence Table */}
              <div className="card">
                <div className="card-title">
                  <span>Authoritative Grounding Citations ({analysisResult.citations?.length || 0})</span>
                  <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>Verbatim source evidence</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {analysisResult.citations?.map((cit, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '10px 12px',
                        borderRadius: '6px',
                        backgroundColor: 'var(--bg-surface-alt)',
                        border: '1px solid var(--border-color)',
                        fontSize: '12px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                        <span style={{ fontWeight: '700', color: 'var(--accent-primary)' }}>
                          [{cit.external_id}] ({cit.citation_role})
                        </span>
                        <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>
                          Source: {cit.source_id}
                        </span>
                      </div>
                      <div style={{ color: 'var(--text-main)', fontStyle: 'italic', lineHeight: '1.4' }}>
                        "{cit.excerpt}"
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Uncertainties & Model Metadata */}
              {rep?.uncertainties?.length > 0 && (
                <div className="card" style={{ backgroundColor: 'var(--bg-surface-alt)' }}>
                  <div className="card-title">
                    <span>Uncertainties & Analytical Limitations</span>
                  </div>
                  <ul style={{ paddingLeft: '20px', fontSize: '12.5px', color: 'var(--text-muted)', lineHeight: '1.6' }}>
                    {rep.uncertainties.map((u, idx) => (
                      <li key={idx}>{u}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Action: Run Another Analysis */}
              <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
                <button className="btn btn-secondary" onClick={() => setActiveStep(1)}>
                  <ArrowLeft size={14} />
                  <span>Start Another Threat Analysis</span>
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
};

export default ThreatModelingWorkspace;
