import React, { useState, useEffect } from 'react';

function DashboardSummary({ token }) {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchDashboard();
  }, []);

  const fetchDashboard = async () => {
    try {
      const response = await fetch('http://localhost:5001/api/v1/dashboard/summary', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setSummary(data);
      } else {
        setError('Failed to load dashboard');
      }
    } catch (err) {
      setError('Network error');
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div className="loading">Loading dashboard...</div>;
  if (error) return <div className="alert-error">{error}</div>;

  return (
    <div>
      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total Students</h3>
          <div className="stat-number">{summary.total_students}</div>
        </div>
        
        <div className="stat-card">
          <h3>Total Teachers</h3>
          <div className="stat-number">{summary.total_teachers}</div>
        </div>
        
        <div className="stat-card">
          <h3>Revenue (USD)</h3>
          <div className="stat-number">${summary.total_revenue_usd?.toFixed(2)}</div>
        </div>
        
        <div className="stat-card">
          <h3>Outstanding Fees</h3>
          <div className="stat-number">${summary.outstanding_fees_usd?.toFixed(2)}</div>
        </div>
      </div>
      
      <div className="card">
        <h3>Students by Class</h3>
        <table>
          <thead>
            <tr>
              <th>Class</th>
              <th>Count</th>
            </tr>
          </thead>
          <tbody>
            {summary.students_by_class?.map((item, index) => (
              <tr key={index}>
                <td>{item.class}</td>
                <td>{item.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      
      {summary.recent_payments?.length > 0 && (
        <div className="card">
          <h3>Recent Payments</h3>
          <table>
            <thead>
              <tr>
                <th>Receipt #</th>
                <th>Student</th>
                <th>Amount</th>
                <th>Date</th>
              </tr>
            </thead>
            <tbody>
              {summary.recent_payments.map((payment, index) => (
                <tr key={index}>
                  <td>{payment.receipt_number}</td>
                  <td>{payment.student_name}</td>
                  <td>{payment.amount} {payment.currency}</td>
                  <td>{new Date(payment.payment_date).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default DashboardSummary;