import React from 'react';

export const MetricCard = ({ label, value, subtext, badge, icon: Icon, color }) => {
  return (
    <div className="card" style={{ position: 'relative' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <div className="metric-label">{label}</div>
          <div className="metric-value" style={{ color: color || 'inherit' }}>
            {value}
          </div>
          {subtext && <div className="metric-subtext">{subtext}</div>}
        </div>
        {Icon && (
          <div
            style={{
              padding: '8px',
              borderRadius: '8px',
              backgroundColor: 'var(--bg-surface-alt)',
              color: color || 'var(--accent-primary)',
            }}
          >
            <Icon size={20} />
          </div>
        )}
      </div>
      {badge && (
        <div style={{ marginTop: '12px' }}>
          <span className="badge badge-demo">{badge}</span>
        </div>
      )}
    </div>
  );
};

export default MetricCard;
