import React, { useState } from 'react';
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';

export const ResilienceQuadrant = ({ points = [], onSelectScenario }) => {
  const [selectedPoint, setSelectedPoint] = useState(null);

  // Custom tooltip
  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div
          style={{
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border-color)',
            padding: '10px 14px',
            borderRadius: '6px',
            boxShadow: 'var(--shadow-md)',
            fontSize: '12px',
          }}
        >
          <div style={{ fontWeight: '700', color: 'var(--text-main)', marginBottom: '4px' }}>
            {data.name}
          </div>
          <div style={{ color: 'var(--text-muted)' }}>
            Detection: <strong>{data.detection_pct}%</strong>
          </div>
          <div style={{ color: 'var(--text-muted)' }}>
            Mitigation: <strong>{data.mitigation_pct}%</strong>
          </div>
          <div style={{ marginTop: '6px' }}>
            <span
              className={`badge ${
                data.status === 'Resilient'
                  ? 'badge-covered'
                  : 'badge-exposed'
              }`}
            >
              {data.status}
            </span>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div style={{ position: 'relative', width: '100%', height: 320 }}>
      {/* Quadrant Labels */}
      <div
        style={{
          position: 'absolute',
          top: 8,
          left: 48,
          fontSize: '10px',
          fontWeight: '700',
          color: '#f59e0b',
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
          pointerEvents: 'none',
        }}
      >
        Paper Tiger (High Det, Low Mit)
      </div>
      <div
        style={{
          position: 'absolute',
          top: 8,
          right: 20,
          fontSize: '10px',
          fontWeight: '700',
          color: '#10b981',
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
          pointerEvents: 'none',
        }}
      >
        Resilient (High Det, High Mit)
      </div>
      <div
        style={{
          position: 'absolute',
          bottom: 24,
          left: 48,
          fontSize: '10px',
          fontWeight: '700',
          color: '#ef4444',
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
          pointerEvents: 'none',
        }}
      >
        High Risk (Low Det, Low Mit)
      </div>
      <div
        style={{
          position: 'absolute',
          bottom: 24,
          right: 20,
          fontSize: '10px',
          fontWeight: '700',
          color: '#0284c7',
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
          pointerEvents: 'none',
        }}
      >
        Silent Well (Low Det, High Mit)
      </div>

      <ResponsiveContainer width="100%" height="100%">
        <ScatterChart margin={{ top: 25, right: 25, bottom: 25, left: 20 }}>
          <XAxis
            type="number"
            dataKey="mitigation_pct"
            name="Mitigation %"
            domain={[0, 100]}
            unit="%"
            stroke="var(--text-muted)"
            fontSize={11}
          />
          <YAxis
            type="number"
            dataKey="detection_pct"
            name="Detection %"
            domain={[0, 100]}
            unit="%"
            stroke="var(--text-muted)"
            fontSize={11}
          />
          <ZAxis range={[70, 70]} />
          <Tooltip content={<CustomTooltip />} />
          {/* Axis center crosshairs */}
          <ReferenceLine x={50} stroke="var(--border-color)" strokeDasharray="3 3" />
          <ReferenceLine y={50} stroke="var(--border-color)" strokeDasharray="3 3" />
          <Scatter
            name="Threat Scenarios"
            data={points}
            fill="#0ea5e9"
            onClick={(point) => {
              setSelectedPoint(point);
              if (onSelectScenario) onSelectScenario(point);
            }}
            cursor="pointer"
          />
        </ScatterChart>
      </ResponsiveContainer>
    </div>
  );
};

export default ResilienceQuadrant;
