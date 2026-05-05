import React, { useState, useEffect } from 'react';
import DashboardSummary from './DashboardSummary';
import Students from './Students';

function Dashboard({ token }) {
  const [activeTab, setActiveTab] = useState('overview');

  return (
    <div>
      <div className="card">
        <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
          <button 
            className={activeTab === 'overview' ? 'btn btn-primary' : 'btn'}
            onClick={() => setActiveTab('overview')}
          >
            Overview
          </button>
          <button 
            className={activeTab === 'students' ? 'btn btn-primary' : 'btn'}
            onClick={() => setActiveTab('students')}
          >
            Students List
          </button>
        </div>
        
        {activeTab === 'overview' && <DashboardSummary token={token} />}
        {activeTab === 'students' && <Students token={token} />}
      </div>
    </div>
  );
}

export default Dashboard;