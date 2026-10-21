import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { FilterProvider } from './context/FilterContext';
import Sidebar from './components/Sidebar';
import TopBar from './components/TopBar';

import ResilienceDashboard from './screens/ResilienceDashboard';
import CoverageMatrix from './screens/CoverageMatrix';
import ThreatExposure from './screens/ThreatExposure';
import ThreatScenarios from './screens/ThreatScenarios';
import ThreatFeeds from './screens/ThreatFeeds';
import ThreatModelingWorkspace from './screens/ThreatModelingWorkspace';
import CompletedReports from './screens/CompletedReports';

export const App = () => {
  return (
    <FilterProvider>
      <BrowserRouter>
        <div className="app-container">
          <Sidebar />
          <div className="main-content">
            <TopBar />
            <Routes>
              {/* Section 1: Identity Threat Insights */}
              <Route path="/" element={<ResilienceDashboard />} />
              <Route path="/coverage-matrix" element={<CoverageMatrix />} />
              <Route path="/threat-exposure" element={<ThreatExposure />} />
              <Route path="/threat-scenarios" element={<ThreatScenarios />} />

              {/* Section 2: Identity Threat Detection & Response Portal */}
              <Route path="/feeds" element={<ThreatFeeds />} />
              <Route path="/threat-modeling" element={<ThreatModelingWorkspace />} />
              <Route path="/reports" element={<CompletedReports />} />

              {/* Fallback */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </div>
        </div>
      </BrowserRouter>
    </FilterProvider>
  );
};

export default App;
