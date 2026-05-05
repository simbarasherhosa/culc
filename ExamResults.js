import React, { useState, useEffect } from 'react';

function ExamResults({ token }) {
  const [students, setStudents] = useState([]);
  const [subjects, setSubjects] = useState([]);
  const [terms, setTerms] = useState([]);
  const [results, setResults] = useState([]);
  const [selectedStudent, setSelectedStudent] = useState('');
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [formData, setFormData] = useState({
    student_id: '',
    subject_id: '',
    term_id: '',
    exam_type: 'end_term',
    score: '',
    remarks: ''
  });

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [studentsRes, subjectsRes, termsRes] = await Promise.all([
        fetch('http://localhost:5001/api/v1/students', { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch('http://localhost:5001/api/v1/subjects', { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch('http://localhost:5001/api/v1/terms', { headers: { 'Authorization': `Bearer ${token}` } })
      ]);
      
      const studentsData = await studentsRes.json();
      const subjectsData = await subjectsRes.json();
      const termsData = await termsRes.json();
      
      setStudents(studentsData);
      setSubjects(subjectsData);
      setTerms(termsData);
    } catch (error) {
      console.error('Error fetching data:', error);
      setError('Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const fetchResults = async (studentId) => {
    try {
      const response = await fetch(`http://localhost:5001/api/v1/students/${studentId}/zimsec-report`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      setResults(data.results || []);
    } catch (error) {
      console.error('Error fetching results:', error);
      setError('Failed to fetch results');
    }
  };

  const handleStudentChange = (e) => {
    const studentId = e.target.value;
    setSelectedStudent(studentId);
    if (studentId) {
      fetchResults(studentId);
    } else {
      setResults([]);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    
    // Validate score is a number
    const score = parseFloat(formData.score);
    if (isNaN(score) || score < 0 || score > 100) {
      setError('Score must be a number between 0 and 100');
      return;
    }
    
    // Prepare data with proper types
    const submitData = {
      student_id: parseInt(formData.student_id, 10),
      subject_id: parseInt(formData.subject_id, 10),
      term_id: parseInt(formData.term_id, 10),
      exam_type: formData.exam_type,
      score: score,
      remarks: formData.remarks || null
    };
    
    console.log('Submitting data:', submitData);
    
    try {
      const response = await fetch('http://localhost:5001/api/v1/exam-results', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(submitData)
      });
      
      const data = await response.json();
      
      if (response.ok) {
        setSuccess('Exam result added successfully!');
        // Reset form
        setFormData({
          student_id: '',
          subject_id: '',
          term_id: '',
          exam_type: 'end_term',
          score: '',
          remarks: ''
        });
        setShowForm(false);
        // Refresh results if a student is selected
        if (selectedStudent) {
          fetchResults(selectedStudent);
        }
        // Clear success message after 3 seconds
        setTimeout(() => setSuccess(''), 3000);
      } else {
        setError(data.error || 'Failed to add exam result');
        console.error('Server error:', data);
      }
    } catch (error) {
      console.error('Error submitting form:', error);
      setError('Network error. Please check if the server is running.');
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const getGradeColor = (grade) => {
    const colors = {
      'A': '#28a745',
      'B': '#17a2b8',
      'C': '#ffc107',
      'D': '#fd7e14',
      'E': '#dc3545',
      'F': '#6c757d'
    };
    return colors[grade] || '#6c757d';
  };

  if (loading) return <div className="loading">Loading exam data...</div>;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h2>📝 Exam Results (ZIMSEC)</h2>
        <button className="btn btn-primary" onClick={() => {
          setShowForm(!showForm);
          setError('');
          setSuccess('');
        }}>
          {showForm ? 'Cancel' : '+ Add Result'}
        </button>
      </div>

      {error && (
        <div className="alert alert-error" style={{ backgroundColor: '#f8d7da', color: '#721c24', padding: '10px', borderRadius: '5px', marginBottom: '1rem' }}>
          ❌ {error}
        </div>
      )}
      
      {success && (
        <div className="alert alert-success" style={{ backgroundColor: '#d4edda', color: '#155724', padding: '10px', borderRadius: '5px', marginBottom: '1rem' }}>
          ✅ {success}
        </div>
      )}

      {showForm && (
        <div className="card">
          <h3>Add Exam Result</h3>
          <form onSubmit={handleSubmit}>
            <div className="form-row">
              <div className="form-group">
                <label>Student *</label>
                <select
                  name="student_id"
                  value={formData.student_id}
                  onChange={handleInputChange}
                  required
                >
                  <option value="">Select Student</option>
                  {students.map(s => <option key={s.id} value={s.id}>{s.full_name} ({s.class_name})</option>)}
                </select>
              </div>
              
              <div className="form-group">
                <label>Subject *</label>
                <select
                  name="subject_id"
                  value={formData.subject_id}
                  onChange={handleInputChange}
                  required
                >
                  <option value="">Select Subject</option>
                  {subjects.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Term *</label>
                <select
                  name="term_id"
                  value={formData.term_id}
                  onChange={handleInputChange}
                  required
                >
                  <option value="">Select Term</option>
                  {terms.map(t => <option key={t.id} value={t.id}>Term {t.term_number} - {t.year}</option>)}
                </select>
              </div>
              
              <div className="form-group">
                <label>Exam Type *</label>
                <select
                  name="exam_type"
                  value={formData.exam_type}
                  onChange={handleInputChange}
                  required
                >
                  <option value="mid_term">Mid Term</option>
                  <option value="end_term">End Term</option>
                  <option value="continuous">Continuous Assessment</option>
                  <option value="zimsec_mock">ZIMSEC Mock</option>
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Score (%) *</label>
                <input
                  type="number"
                  name="score"
                  step="0.01"
                  min="0"
                  max="100"
                  value={formData.score}
                  onChange={handleInputChange}
                  required
                />
              </div>
              
              <div className="form-group">
                <label>Remarks</label>
                <input
                  type="text"
                  name="remarks"
                  value={formData.remarks}
                  onChange={handleInputChange}
                  placeholder="Optional remarks"
                />
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <button type="submit" className="btn btn-primary">Add Result</button>
              <button type="button" className="btn btn-secondary" onClick={() => setShowForm(false)}>
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="card">
        <h3>View Student Results</h3>
        <div className="form-group">
          <label>Select Student</label>
          <select value={selectedStudent} onChange={handleStudentChange}>
            <option value="">Choose a student...</option>
            {students.map(s => <option key={s.id} value={s.id}>{s.full_name} - {s.class_name}</option>)}
          </select>
        </div>

        {selectedStudent && (
          <div>
            <h4>Results</h4>
            {results.length === 0 ? (
              <p>No results recorded for this student yet.</p>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table className="results-table">
                  <thead>
                    <tr>
                      <th>Subject</th>
                      <th>Exam Type</th>
                      <th>Score (%)</th>
                      <th>Grade</th>
                      <th>Points</th>
                      <th>Remarks</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((result, idx) => (
                      <tr key={idx}>
                        <td>{result.subject}</td>
                        <td>{result.exam_type}</td>
                        <td>{result.score}%</td>
                        <td>
                          <span className="badge" style={{ background: getGradeColor(result.zimsec_grade), color: 'white', padding: '5px 10px', borderRadius: '3px' }}>
                            {result.zimsec_grade}
                          </span>
                        </td>
                        <td>{result.points}</td>
                        <td>{result.remarks || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default ExamResults;