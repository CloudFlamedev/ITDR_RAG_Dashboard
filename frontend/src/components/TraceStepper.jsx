import React from 'react';
import { CheckCircle2, Clock, AlertCircle } from 'lucide-react';

export const TraceStepper = ({ traceSteps = [] }) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      <div style={{ fontSize: '12px', fontWeight: '700', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '4px' }}>
        LangGraph Observable Workflow Stepper ({traceSteps.length} nodes)
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '8px' }}>
        {traceSteps.map((step, idx) => {
          const isSuccess = step.status === 'SUCCESS' || step.status === 'COMPLETED';
          const isFailed = step.status === 'FAILED' || step.status === 'ERROR';

          return (
            <div
              key={idx}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 10px',
                borderRadius: '6px',
                backgroundColor: 'var(--bg-surface-alt)',
                border: '1px solid var(--border-color)',
                fontSize: '11.5px',
              }}
            >
              {isSuccess ? (
                <CheckCircle2 size={14} color="var(--accent-success)" />
              ) : isFailed ? (
                <AlertCircle size={14} color="var(--accent-danger)" />
              ) : (
                <Clock size={14} color="var(--text-muted)" />
              )}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: '600', color: 'var(--text-main)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {step.step_name}
                </div>
                <div style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>
                  {step.duration_ms}ms • {step.status}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default TraceStepper;
