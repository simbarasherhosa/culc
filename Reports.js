import React, { useState, useEffect } from 'react';

function Reports({ token }) {
  const [students, setStudents] = useState([]);
  const [selectedStudent, setSelectedStudent] = useState('');
  const [academicReport, setAcademicReport] = useState(null);
  const [financialReport, setFinancialReport] = useState(null);
  const [sportsReport, setSportsReport] = useState(null);
  const [ministryReport, setMinistryReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [reportType, setReportType] = useState('academic');
  const [error, setError] = useState('');
  const [dateRange, setDateRange] = useState({
    start_date: '',
    end_date: ''
  });

  useEffect(() => {
    if (token) {
      fetchStudents();
    } else {
      setError('Authentication token not found. Please log in again.');
    }
  }, [token]);

  const fetchStudents = async () => {
    if (!token) return;
    
    setLoading(true);
    setError('');
    
    try {
      const response = await fetch('http://localhost:5001/api/v1/students', {
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
      const data = await response.json();
      
      if (Array.isArray(data)) {
        setStudents(data);
      } else if (data.students) {
        setStudents(data.students);
      } else {
        setStudents([]);
      }
    } catch (error) {
      console.error('Error fetching students:', error);
      setError(`Failed to load students: ${error.message}`);
      setStudents([]);
    } finally {
      setLoading(false);
    }
  };

  const generateReport = async () => {
    if (!token) {
      setError('Authentication token not found');
      return;
    }
    
    if (reportType === 'academic' && !selectedStudent) {
      setError('Please select a student');
      return;
    }
    
    setLoading(true);
    setError('');
    
    try {
      let url = '';
      let response;
      
      switch (reportType) {
        case 'academic':
          url = `http://localhost:5001/api/v1/reports/academic/${selectedStudent}`;
          if (dateRange.start_date) {
            url += `?start_date=${dateRange.start_date}&end_date=${dateRange.end_date}`;
          }
          response = await fetch(url, { 
            headers: { 
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json'
            } 
          });
          if (response.ok) {
            const data = await response.json();
            setAcademicReport(data);
            setFinancialReport(null);
            setSportsReport(null);
            setMinistryReport(null);
          } else {
            const error = await response.json();
            throw new Error(error.error || 'Failed to generate academic report');
          }
          break;
          
        case 'financial':
          url = 'http://localhost:5001/api/v1/reports/financial';
          if (dateRange.start_date) {
            url += `?start_date=${dateRange.start_date}&end_date=${dateRange.end_date}`;
          }
          response = await fetch(url, { 
            headers: { 
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json'
            } 
          });
          if (response.ok) {
            const data = await response.json();
            setFinancialReport(data);
            setAcademicReport(null);
            setSportsReport(null);
            setMinistryReport(null);
          } else {
            const error = await response.json();
            throw new Error(error.error || 'Failed to generate financial report');
          }
          break;
          
        case 'sports':
          response = await fetch('http://localhost:5001/api/v1/reports/sports-participation', {
            headers: { 
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json'
            }
          });
          if (response.ok) {
            const data = await response.json();
            console.log('Sports report data:', data); // Debug log
            setSportsReport(data);
            setAcademicReport(null);
            setFinancialReport(null);
            setMinistryReport(null);
          } else {
            const error = await response.json();
            throw new Error(error.error || 'Failed to generate sports report');
          }
          break;
          
        case 'ministry':
          const year = dateRange.start_date ? new Date(dateRange.start_date).getFullYear() : new Date().getFullYear();
          response = await fetch(`http://localhost:5001/api/v1/reports/ministry-compliance?year=${year}`, {
            headers: { 
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json'
            }
          });
          if (response.ok) {
            const data = await response.json();
            setMinistryReport(data);
            setAcademicReport(null);
            setFinancialReport(null);
            setSportsReport(null);
          } else {
            const error = await response.json();
            throw new Error(error.error || 'Failed to generate ministry report');
          }
          break;
          
        default:
          throw new Error('Invalid report type');
      }
    } catch (error) {
      console.error('Error generating report:', error);
      setError(error.message || 'Error generating report');
    } finally {
      setLoading(false);
    }
  };

  const exportReport = async (type) => {
    if (!token) {
      setError('Authentication token not found');
      return;
    }
    
    setLoading(true);
    setError('');
    
    try {
      const response = await fetch(`http://localhost:5001/api/v1/reports/export/${type}`, {
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Export failed');
      }
      
      const data = await response.json();
      
      const blob = new Blob([data.data], { type: 'text/csv;charset=utf-8;' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${type}_report_${new Date().toISOString().split('T')[0]}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      
      alert('Report exported successfully!');
    } catch (error) {
      console.error('Error exporting report:', error);
      setError(error.message || 'Error exporting report');
    } finally {
      setLoading(false);
    }
  };

  // Helper function to safely format numbers
  const formatNumber = (value, decimals = 2) => {
    if (value === undefined || value === null) return '0.00';
    const num = typeof value === 'number' ? value : parseFloat(value);
    return isNaN(num) ? '0.00' : num.toFixed(decimals);
  };

  return (
    <div>
      <h2>📈 Reports & Analytics</h2>
      
      {error && (
        <div className="alert alert-error" style={{ 
          backgroundColor: '#f8d7da', 
          color: '#721c24', 
          padding: '10px', 
          borderRadius: '5px', 
          marginBottom: '1rem',
          border: '1px solid #f5c6cb'
        }}>
          ❌ {error}
        </div>
      )}
      
      <div className="card">
        <h3>Generate Report</h3>
        <div className="form-row">
          <div className="form-group">
            <label>Report Type</label>
            <select 
              value={reportType} 
              onChange={(e) => {
                setReportType(e.target.value);
                setAcademicReport(null);
                setFinancialReport(null);
                setSportsReport(null);
                setMinistryReport(null);
                setError('');
              }}
            >
              <option value="academic">Academic Report (Student)</option>
              <option value="financial">Financial Report</option>
              <option value="sports">Sports Participation</option>
              <option value="ministry">Ministry Compliance</option>
            </select>
          </div>
          
          {reportType === 'academic' && (
            <div className="form-group">
              <label>Select Student *</label>
              <select 
                value={selectedStudent} 
                onChange={(e) => setSelectedStudent(e.target.value)}
                disabled={loading || students.length === 0}
              >
                <option value="">{students.length === 0 ? 'Loading students...' : 'Choose Student'}</option>
                {students.map(s => (
                  <option key={s.id} value={s.id}>
                    {s.full_name} {s.class_name ? `- ${s.class_name}` : ''}
                  </option>
                ))}
              </select>
            </div>
          )}
          
          {(reportType === 'academic' || reportType === 'financial') && (
            <>
              <div className="form-group">
                <label>Start Date (Optional)</label>
                <input
                  type="date"
                  value={dateRange.start_date}
                  onChange={(e) => setDateRange({...dateRange, start_date: e.target.value})}
                />
              </div>
              <div className="form-group">
                <label>End Date (Optional)</label>
                <input
                  type="date"
                  value={dateRange.end_date}
                  onChange={(e) => setDateRange({...dateRange, end_date: e.target.value})}
                />
              </div>
            </>
          )}
        </div>
        
        <div style={{ display: 'flex', gap: '1rem' }}>
          <button 
            className="btn btn-primary" 
            onClick={generateReport}
            disabled={loading || (reportType === 'academic' && !selectedStudent)}
          >
            {loading ? 'Generating...' : 'Generate Report'}
          </button>
          
          {reportType !== 'ministry' && reportType !== 'sports' && (
            <button 
              className="btn btn-secondary" 
              onClick={() => exportReport(reportType === 'academic' ? 'students' : 'fees')}
              disabled={loading}
            >
              📥 Export CSV
            </button>
          )}
        </div>
      </div>

      {/* Academic Report */}
      {academicReport && academicReport.results && (
        <div className="card">
          <h3>📚 Academic Report</h3>
          <div className="report-header">
            <p><strong>Student ID:</strong> {academicReport.student_id}</p>
            <p><strong>Generated:</strong> {new Date(academicReport.generated_at).toLocaleString()}</p>
          </div>
          
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-number">{academicReport.academic?.subjects || 0}</div>
              <div>Subjects Taken</div>
            </div>
            <div className="stat-card">
              <div className="stat-number">{academicReport.academic?.total_points || 0}</div>
              <div>Total Points</div>
            </div>
            <div className="stat-card">
              <div className="stat-number">{formatNumber(academicReport.academic?.average_score)}%</div>
              <div>Average Score</div>
            </div>
            <div className="stat-card">
              <div className="stat-number">{formatNumber(academicReport.attendance?.attendance_rate)}%</div>
              <div>Attendance Rate</div>
            </div>
          </div>
          
          {academicReport.results && academicReport.results.length > 0 && (
            <>
              <h4>Exam Results</h4>
              <div style={{ overflowX: 'auto' }}>
                <table className="report-table">
                  <thead>
                    <tr>
                      <th>Subject</th>
                      <th>Score</th>
                      <th>Grade</th>
                      <th>Points</th>
                    </tr>
                  </thead>
                  <tbody>
                    {academicReport.results.map((result, idx) => (
                      <tr key={idx}>
                        <td>{result.subject || 'Unknown'}</td>
                        <td>{result.score}%</td>
                        <td><strong>{result.zimsec_grade}</strong></td>
                        <td>{result.points}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}

      {/* Financial Report - Fixed toFixed error */}
      {financialReport && (
        <div className="card">
          <h3>💰 Financial Report</h3>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-number">
                ${formatNumber(financialReport.total_collections_usd)}
              </div>
              <div>Total Collections (USD)</div>
            </div>
            <div className="stat-card">
              <div className="stat-number">
                ZWG {formatNumber(financialReport.total_collections_zwg)}
              </div>
              <div>Total Collections (ZWG)</div>
            </div>
            <div className="stat-card">
              <div className="stat-number">{financialReport.total_transactions || 0}</div>
              <div>Total Transactions</div>
            </div>
          </div>
          
          {financialReport.breakdown_by_method && Object.keys(financialReport.breakdown_by_method).length > 0 && (
            <>
              <h4>Breakdown by Payment Method</h4>
              <div style={{ overflowX: 'auto' }}>
                <table className="report-table">
                  <thead>
                    <tr>
                      <th>Method</th>
                      <th>Total (USD)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(financialReport.breakdown_by_method).map(([method, amount]) => (
                      <tr key={method}>
                        <td>{method.toUpperCase()}</td>
                        <td>${formatNumber(amount)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}

      {/* Sports Report - Fixed to handle empty data */}
      {sportsReport && (
        <div className="card">
          <h3>⚽ Sports Participation Report</h3>
          {sportsReport.length === 0 ? (
            <p>No sports participation data available.</p>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="report-table">
                <thead>
                  <tr>
                    <th>Sport</th>
                    <th>Participants</th>
                  </tr>
                </thead>
                <tbody>
                  {sportsReport.map((sport, idx) => (
                    <tr key={idx}>
                      <td>{sport.sport}</td>
                      <td>{sport.participants}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Ministry Compliance Report */}
      {ministryReport && (
        <div className="card">
          <h3>🏛️ Ministry Compliance Report</h3>
          <p><strong>School:</strong> {ministryReport.school_name}</p>
          <p><strong>Reporting Year:</strong> {ministryReport.reporting_year}</p>
          <p><strong>Report Date:</strong> {new Date(ministryReport.report_date).toLocaleString()}</p>
          
          <h4>Enrollment Statistics</h4>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-number">{ministryReport.enrollment?.total_students || 0}</div>
              <div>Total Students</div>
            </div>
            <div className="stat-card">
              <div className="stat-number">{ministryReport.staffing?.total_teachers || 0}</div>
              <div>Total Teachers</div>
            </div>
          </div>
          
          {ministryReport.enrollment?.by_gender && ministryReport.enrollment.by_gender.length > 0 && (
            <>
              <h5>Students by Gender</h5>
              <ul>
                {ministryReport.enrollment.by_gender.map((g, idx) => (
                  <li key={idx}>{g.gender}: {g.count} students</li>
                ))}
              </ul>
            </>
          )}
          
          {ministryReport.academic_performance && ministryReport.academic_performance.length > 0 && (
            <>
              <h5>Academic Performance</h5>
              <div style={{ overflowX: 'auto' }}>
                <table className="report-table">
                  <thead>
                    <tr>
                      <th>Subject</th>
                      <th>Average Score</th>
                      <th>Total Exams</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ministryReport.academic_performance.map((subj, idx) => (
                      <tr key={idx}>
                        <td>{subj.subject}</td>
                        <td>{subj.average_score}%</td>
                        <td>{subj.total_exams}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
          
          <div className="alert alert-success" style={{ marginTop: '1rem', padding: '1rem', backgroundColor: '#d4edda', color: '#155724', borderRadius: '4px' }}>
            ✅ Compliance Status: {ministryReport.compliance_status || 'Compliant'}
          </div>
        </div>
      )}
    </div>
  );
}

export default Reports;