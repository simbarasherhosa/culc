import React, { useState, useEffect } from 'react';

function Students({ token }) {
  const [students, setStudents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchStudents();
  }, []);

  const fetchStudents = async () => {
    try {
      const response = await fetch('http://localhost:5001/api/v1/students', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setStudents(data);
      } else {
        setError('Failed to load students');
      }
    } catch (err) {
      setError('Network error');
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div className="loading">Loading students...</div>;
  if (error) return <div className="alert-error">{error}</div>;

  return (
    <div>
      <h2>Student Directory</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Full Name</th>
            <th>National ID</th>
            <th>Class</th>
            <th>Stream</th>
            <th>Phone</th>
            <th>Guardian</th>
          </tr>
        </thead>
        <tbody>
          {students.map((student) => (
            <tr key={student.id}>
              <td>{student.id}</td>
              <td><strong>{student.full_name}</strong></td>
              <td>{student.national_id || 'N/A'}</td>
              <td>{student.class_name || 'N/A'}</td>
              <td>{student.stream || 'N/A'}</td>
              <td>{student.phone || 'N/A'}</td>
              <td>{student.guardian_name || 'N/A'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {students.length === 0 && (
        <p style={{textAlign: 'center', padding: '2rem'}}>No students found. Add your first student!</p>
      )}
    </div>
  );
}

export default Students;