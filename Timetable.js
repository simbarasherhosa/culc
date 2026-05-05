import React, { useState, useEffect } from 'react';

function Timetable({ token }) {
  const [timetable, setTimetable] = useState([]);
  const [subjects, setSubjects] = useState([]);
  const [teachers, setTeachers] = useState([]);
  const [terms, setTerms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({
    class_name: '',
    subject_id: '',
    teacher_id: '',
    day_of_week: 'Monday',
    start_time: '08:00',
    end_time: '09:30',
    room: '',
    term_id: ''
  });

  const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'];
  const classes = ['Form 1', 'Form 2', 'Form 3', 'Form 4'];

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [timetableRes, subjectsRes, teachersRes, termsRes] = await Promise.all([
        fetch('http://localhost:5001/api/v1/timetable', { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch('http://localhost:5001/api/v1/subjects', { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch('http://localhost:5001/api/v1/teachers', { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch('http://localhost:5001/api/v1/terms', { headers: { 'Authorization': `Bearer ${token}` } })
      ]);
      
      const timetableData = await timetableRes.json();
      const subjectsData = await subjectsRes.json();
      const teachersData = await teachersRes.json();
      const termsData = await termsRes.json();
      
      setTimetable(timetableData);
      setSubjects(subjectsData);
      setTeachers(teachersData);
      setTerms(termsData);
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('http://localhost:5001/api/v1/timetable', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(formData)
      });
      
      if (response.ok) {
        alert('Timetable entry added successfully!');
        setShowForm(false);
        fetchData();
        setFormData({
          class_name: '',
          subject_id: '',
          teacher_id: '',
          day_of_week: 'Monday',
          start_time: '08:00',
          end_time: '09:30',
          room: '',
          term_id: ''
        });
      } else {
        alert('Failed to add timetable entry');
      }
    } catch (error) {
      console.error('Error:', error);
    }
  };

  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to delete this entry?')) {
      try {
        const response = await fetch(`http://localhost:5001/api/v1/timetable/${id}`, {
          method: 'DELETE',
          headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (response.ok) {
          alert('Entry deleted successfully!');
          fetchData();
        } else {
          alert('Failed to delete entry');
        }
      } catch (error) {
        console.error('Error:', error);
      }
    }
  };

  if (loading) return <div className="loading">Loading timetable...</div>;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h2>📅 School Timetable</h2>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? 'Cancel' : '+ Add Entry'}
        </button>
      </div>

      {showForm && (
        <div className="card">
          <h3>Add Timetable Entry</h3>
          <form onSubmit={handleSubmit}>
            <div className="form-row">
              <div className="form-group">
                <label>Class *</label>
                <select
                  value={formData.class_name}
                  onChange={(e) => setFormData({...formData, class_name: e.target.value})}
                  required
                >
                  <option value="">Select Class</option>
                  {classes.map(c => <option key={c} value={c}>{c}</option>)}
                </select>
              </div>
              
              <div className="form-group">
                <label>Subject *</label>
                <select
                  value={formData.subject_id}
                  onChange={(e) => setFormData({...formData, subject_id: e.target.value})}
                  required
                >
                  <option value="">Select Subject</option>
                  {subjects.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Teacher *</label>
                <select
                  value={formData.teacher_id}
                  onChange={(e) => setFormData({...formData, teacher_id: e.target.value})}
                  required
                >
                  <option value="">Select Teacher</option>
                  {teachers.map(t => <option key={t.id} value={t.id}>{t.full_name}</option>)}
                </select>
              </div>
              
              <div className="form-group">
                <label>Day *</label>
                <select
                  value={formData.day_of_week}
                  onChange={(e) => setFormData({...formData, day_of_week: e.target.value})}
                  required
                >
                  {days.map(d => <option key={d} value={d}>{d}</option>)}
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Start Time *</label>
                <input
                  type="time"
                  value={formData.start_time}
                  onChange={(e) => setFormData({...formData, start_time: e.target.value})}
                  required
                />
              </div>
              
              <div className="form-group">
                <label>End Time *</label>
                <input
                  type="time"
                  value={formData.end_time}
                  onChange={(e) => setFormData({...formData, end_time: e.target.value})}
                  required
                />
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Room</label>
                <input
                  type="text"
                  value={formData.room}
                  onChange={(e) => setFormData({...formData, room: e.target.value})}
                  placeholder="e.g., Room 101"
                />
              </div>
              
              <div className="form-group">
                <label>Term *</label>
                <select
                  value={formData.term_id}
                  onChange={(e) => setFormData({...formData, term_id: e.target.value})}
                  required
                >
                  <option value="">Select Term</option>
                  {terms.map(t => <option key={t.id} value={t.id}>Term {t.term_number} - {t.year}</option>)}
                </select>
              </div>
            </div>

            <button type="submit" className="btn btn-primary">Add Entry</button>
          </form>
        </div>
      )}

      <div className="card">
        <h3>Timetable</h3>
        {timetable.length === 0 ? (
          <p>No timetable entries found. Add some entries above.</p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table>
              <thead>
                <tr>
                  <th>Class</th>
                  <th>Subject</th>
                  <th>Teacher</th>
                  <th>Day</th>
                  <th>Time</th>
                  <th>Room</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {timetable.map(entry => (
                  <tr key={entry.id}>
                    <td>{entry.class_name}</td>
                    <td>{entry.subject}</td>
                    <td>{entry.teacher}</td>
                    <td>{entry.day_of_week}</td>
                    <td>{entry.start_time} - {entry.end_time}</td>
                    <td>{entry.room || 'N/A'}</td>
                    <td>
                      <button 
                        className="btn-danger" 
                        style={{ padding: '0.25rem 0.5rem', fontSize: '0.8rem' }}
                        onClick={() => handleDelete(entry.id)}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default Timetable;