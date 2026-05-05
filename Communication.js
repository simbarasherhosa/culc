import React, { useState, useEffect } from 'react';

function Communication({ token }) {
  const [students, setStudents] = useState([]);
  const [teachers, setTeachers] = useState([]);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [formData, setFormData] = useState({
    recipient_type: 'all_students',
    message_type: 'email',  // Fixed to email only
    subject: '',
    message: '',
    class_name: '',
    recipient_id: ''
  });

  useEffect(() => {
    if (token) {
      fetchData();
    }
  }, [token]);

  const fetchData = async () => {
    if (!token) return;
    
    setLoading(true);
    try {
      const [studentsRes, teachersRes, logsRes] = await Promise.all([
        fetch('http://localhost:5001/api/v1/students', { 
          headers: { 'Authorization': `Bearer ${token}` } 
        }),
        fetch('http://localhost:5001/api/v1/teachers', { 
          headers: { 'Authorization': `Bearer ${token}` } 
        }),
        fetch('http://localhost:5001/api/v1/communication/logs', { 
          headers: { 'Authorization': `Bearer ${token}` } 
        })
      ]);
      
      if (studentsRes.ok) setStudents(await studentsRes.json());
      if (teachersRes.ok) setTeachers(await teachersRes.json());
      if (logsRes.ok) setLogs(await logsRes.json());
    } catch (error) {
      console.error('Error fetching data:', error);
      setError('Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    
    // Validate required fields
    if (!formData.subject.trim()) {
      setError('Subject is required');
      setLoading(false);
      return;
    }
    
    if (!formData.message.trim()) {
      setError('Message is required');
      setLoading(false);
      return;
    }
    
    if (formData.recipient_type === 'specific' && !formData.recipient_id) {
      setError('Please select a recipient');
      setLoading(false);
      return;
    }
    
    if (formData.recipient_type === 'class' && !formData.class_name) {
      setError('Please select a class');
      setLoading(false);
      return;
    }
    
    try {
      const submitData = {
        ...formData,
        message_type: 'email'  // Force email only
      };
      
      const response = await fetch('http://localhost:5001/api/v1/communication/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(submitData)
      });
      
      const result = await response.json();
      
      if (response.ok) {
        alert(`✅ ${result.message}`);
        // Reset form
        setFormData({
          recipient_type: 'all_students',
          message_type: 'email',
          subject: '',
          message: '',
          class_name: '',
          recipient_id: ''
        });
        // Refresh logs
        fetchData();
      } else {
        setError(result.error || 'Failed to send email');
      }
    } catch (error) {
      console.error('Error:', error);
      setError('Error sending email. Please check your connection.');
    } finally {
      setLoading(false);
    }
  };

  const getMessageIcon = () => {
    return '📧'; // Email icon only
  };

  const classes = ['Form 1', 'Form 2', 'Form 3', 'Form 4'];

  return (
    <div>
      <h2>📧 Email Communication System</h2>
      
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
      
      <div className="stats-grid">
        <div className="card">
          <h3>Send Email</h3>
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label>Recipient Type *</label>
              <select
                value={formData.recipient_type}
                onChange={(e) => setFormData({...formData, recipient_type: e.target.value, recipient_id: '', class_name: ''})}
              >
                <option value="all_students">All Students (Parents' Email)</option>
                <option value="all_teachers">All Teachers</option>
                <option value="class">Specific Class</option>
                <option value="specific">Specific Student/Teacher</option>
              </select>
            </div>

            {formData.recipient_type === 'class' && (
              <div className="form-group">
                <label>Select Class</label>
                <select
                  value={formData.class_name}
                  onChange={(e) => setFormData({...formData, class_name: e.target.value})}
                  required
                >
                  <option value="">Choose Class</option>
                  {classes.map(c => <option key={c} value={c}>{c}</option>)}
                </select>
              </div>
            )}

            {formData.recipient_type === 'specific' && (
              <div className="form-group">
                <label>Select Recipient</label>
                <select
                  value={formData.recipient_id}
                  onChange={(e) => setFormData({...formData, recipient_id: e.target.value})}
                  required
                >
                  <option value="">Choose Recipient</option>
                  <optgroup label="Students">
                    {students.map(s => (
                      <option key={`s-${s.id}`} value={`student_${s.id}`}>
                        🎓 {s.full_name} - {s.guardian_email || 'No email'}
                      </option>
                    ))}
                  </optgroup>
                  <optgroup label="Teachers">
                    {teachers.map(t => (
                      <option key={`t-${t.id}`} value={`teacher_${t.id}`}>
                        👩‍🏫 {t.full_name} - {t.email || 'No email'}
                      </option>
                    ))}
                  </optgroup>
                </select>
                <small style={{ color: '#666' }}>
                  Note: Only recipients with email addresses will receive the message
                </small>
              </div>
            )}

            <div className="form-group">
              <label>Subject *</label>
              <input
                type="text"
                value={formData.subject}
                onChange={(e) => setFormData({...formData, subject: e.target.value})}
                required
                placeholder="Email subject"
                style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: '4px' }}
              />
            </div>

            <div className="form-group">
              <label>Message *</label>
              <textarea
                value={formData.message}
                onChange={(e) => setFormData({...formData, message: e.target.value})}
                rows="6"
                required
                placeholder="Type your email message here..."
                style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: '4px', fontFamily: 'inherit' }}
              />
            </div>

            <button 
              type="submit" 
              className="btn btn-primary"
              disabled={loading}
              style={{ 
                padding: '10px 20px',
                backgroundColor: '#007bff',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: loading ? 'not-allowed' : 'pointer',
                opacity: loading ? 0.6 : 1
              }}
            >
              {loading ? 'Sending...' : `${getMessageIcon()} Send Email`}
            </button>
          </form>
        </div>

        <div className="card">
          <h3>Recent Email Logs</h3>
          {loading && logs.length === 0 ? (
            <p>Loading...</p>
          ) : logs.length === 0 ? (
            <p>No emails sent yet.</p>
          ) : (
            <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
              {logs.map(log => (
                <div key={log.id} style={{ 
                  marginBottom: '1rem', 
                  padding: '0.75rem', 
                  background: log.status === 'sent' ? '#f0f7ff' : '#fff3cd', 
                  borderRadius: '5px',
                  border: `1px solid ${log.status === 'sent' ? '#cce5ff' : '#ffeeba'}`
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '5px' }}>
                    <strong>📧 {log.subject}</strong>
                    <span className="badge" style={{ 
                      background: log.status === 'sent' ? '#28a745' : '#ffc107',
                      color: 'white',
                      padding: '2px 8px',
                      borderRadius: '3px',
                      fontSize: '11px'
                    }}>
                      {log.status}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: '#666', marginTop: '5px' }}>
                    <div><strong>To:</strong> {log.recipient_name || 'N/A'}</div>
                    <div><strong>Email:</strong> {log.recipient_email || 'No email'}</div>
                    <div><strong>Sent:</strong> {new Date(log.sent_at).toLocaleString()}</div>
                    {log.delivery_report && (
                      <div><strong>Status:</strong> {log.delivery_report}</div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <h3>Email Templates</h3>
        <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))' }}>
          <div className="stat-card" style={{ textAlign: 'left', padding: '1rem' }}>
            <h4>💰 Fee Reminder</h4>
            <p><small>Dear Parent/Guardian, this is a reminder that school fees are due. Please ensure timely payment.</small></p>
            <button 
              className="btn btn-secondary" 
              style={{ marginTop: '0.5rem', padding: '5px 10px', fontSize: '12px' }}
              onClick={() => {
                setFormData({
                  ...formData,
                  subject: 'Fee Payment Reminder',
                  message: 'Dear Parent/Guardian,\n\nThis is a friendly reminder that school fees are due. Please ensure payment is made by the due date to avoid penalties.\n\nIf you have already made the payment, please disregard this message.\n\nThank you for your cooperation.\n\nBest regards,\nCraft Cart School Administration'
                });
              }}
            >
              Use Template
            </button>
          </div>
          
          <div className="stat-card" style={{ textAlign: 'left', padding: '1rem' }}>
            <h4>🎉 Event Announcement</h4>
            <p><small>Dear Parents, the school will be hosting [event] on [date]. Your attendance is highly appreciated.</small></p>
            <button 
              className="btn btn-secondary" 
              style={{ marginTop: '0.5rem', padding: '5px 10px', fontSize: '12px' }}
              onClick={() => {
                setFormData({
                  ...formData,
                  subject: 'School Event Announcement',
                  message: 'Dear Parents/Guardians,\n\nWe are pleased to invite you to our upcoming school event. Details will be shared soon.\n\nYour presence would be greatly appreciated.\n\nBest regards,\nCraft Cart School'
                });
              }}
            >
              Use Template
            </button>
          </div>
          
          <div className="stat-card" style={{ textAlign: 'left', padding: '1rem' }}>
            <h4>📊 Exam Results</h4>
            <p><small>Dear Parent, your child's exam results are now available. Please check the portal for details.</small></p>
            <button 
              className="btn btn-secondary" 
              style={{ marginTop: '0.5rem', padding: '5px 10px', fontSize: '12px' }}
              onClick={() => {
                setFormData({
                  ...formData,
                  subject: 'Exam Results Available',
                  message: 'Dear Parent/Guardian,\n\nYour child\'s examination results have been released. Please log in to the school portal to view the results.\n\nIf you need assistance accessing the portal, please contact the school administration.\n\nRegards,\nCraft Cart School'
                });
              }}
            >
              Use Template
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Communication;