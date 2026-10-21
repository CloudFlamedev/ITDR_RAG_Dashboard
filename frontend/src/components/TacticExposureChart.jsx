import React from 'react';

export const TacticExposureChart = ({ tacticBars = [] }) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '16px', fontSize: '11.5px', marginBottom: '4px' }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
          <span style={{ width: '10px', height: '10px', backgroundColor: 'var(--accent-teal)', borderRadius: '2px' }} />
          Covered
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
          <span style={{ width: '10px', height: '10px', backgroundColor: 'var(--accent-danger)', borderRadius: '2px' }} />
          Exposed (Gap)
        </span>
      </div>

      {tacticBars.slice(0, 8).map((tac) => {
        const coveredWidth = tac.total > 0 ? (tac.covered / tac.total) * 100 : 0;
        const exposedWidth = 100 - coveredWidth;

        return (
          <div key={tac.tactic_id} style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{ width: '140px', fontSize: '12px', fontWeight: '600', color: 'var(--text-main)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={tac.tactic_name}>
              {tac.tactic_name}
            </div>

            <div
              style={{
                flex: 1,
                height: '14px',
                backgroundColor: 'var(--border-color)',
                borderRadius: '3px',
                display: 'flex',
                overflow: 'hidden',
              }}
            >
              {coveredWidth > 0 && (
                <div
                  style={{
                    width: `${coveredWidth}%`,
                    backgroundColor: 'var(--accent-teal)',
                    transition: 'width 0.5s ease',
                  }}
                  title={`Covered: ${tac.covered} / ${tac.total}`}
                />
              )}
              {exposedWidth > 0 && (
                <div
                  style={{
                    width: `${exposedWidth}%`,
                    backgroundColor: 'var(--accent-danger)',
                    transition: 'width 0.5s ease',
                  }}
                  title={`Exposed: ${tac.exposed} / ${tac.total}`}
                />
              )}
            </div>

            <div style={{ width: '60px', textAlign: 'right', fontSize: '11px', fontWeight: '600', color: 'var(--text-muted)' }}>
              {tac.covered}/{tac.total}
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default TacticExposureChart;
