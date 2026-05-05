import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

function StudentForm({ token }) {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    full_name: '',
    national_id: '',
    class_name: '',
    stream: '',
    phone: '',
    guardian_name: '',
    guardian_phone: '',
    guardian_email: '',
    address: '',
    gender: ''
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      const response = await fetch('http://localhost:5001/api/v1/students', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(formData)
      });

      if (response.ok) {
        setMessage({ type: 'success', text: 'Student created successfully!' });
        setTimeout(() => {
          navigate('/students');
        }, 1500);
      } else {
        const error = await response.json();
        setMessage({ type: 'error', text: error.error || 'Failed to create student' });
      }
    } catch (err) {
      setMessage({ type: 'error', text: 'Network error' });
    } finally {
      setLoading(false);
    }
  };
  // Add this helper function at the top of StudentForm.js
  const validateNationalId = (id) => {
    const pattern = /^\d{2}-\d{6,7}[A-Z]\d{2}$/;
    return pattern.test(id);
  };

  // Add this to your handleSubmit function (before submitting)
  if (formData.national_id && !validateNationalId(formData.national_id)) {
    setMessage({ type: 'error', text: 'Invalid National ID format. Expected format: 00-000000A00' });
    return;
  }

  return (
    <div className="card">
      <h2>Add New Student</h2>
      
      {message && (
        <div className={`alert alert-${message.type}`}>
          {message.text}
        </div>
      )}
      
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>Full Name *</label>
          <input
            type="text"
            name="full_name"
            value={formData.full_name}
            onChange={handleChange}
            required
          />
        </div>
        
        <div className="form-group">
          <label>National ID (Optional - Format: 00-000000A00)</label>
          <input
            type="text"
            name="national_id"
            value={formData.national_id}
            onChange={handleChange}
            placeholder="e.g., 50-1234567A90"
          />
        </div>
        
        <div className="form-group">
          <label>Class</label>
          <select name="class_name" value={formData.class_name} onChange={handleChange}>
            <option value="">Select Class</option>
            <option value="Form 1">Form 1</option>
            <option value="Form 2">Form 2</option>
            <option value="Form 3">Form 3</option>
            <option value="Form 4">Form 4</option>
          </select>
        </div>
        
        <div className="form-group">
          <label>Stream</label>
          <select name="stream" value={formData.stream} onChange={handleChange}>
            <option value="">Select Stream</option>
            <option value="A">A</option>
            <option value="B">B</option>
            <option value="C">C</option>
          </select>
        </div>
        
        <div className="form-group">
          <label>Gender</label>
          <select name="gender" value={formData.gender} onChange={handleChange}>
            <option value="">Select Gender</option>
            <option value="Male">Male</option>
            <option value="Female">Female</option>
          </select>
        </div>
        
        <div className="form-group">
          <label>Phone</label>
          <input
            type="tel"
            name="phone"
            value={formData.phone}
            onChange={handleChange}
            placeholder="+263712345678"
          />
        </div>
        
        <div className="form-group">
          <label>Guardian Name</label>
          <input
            type="text"
            name="guardian_name"
            value={formData.guardian_name}
            onChange={handleChange}
          />
        </div>
        
        <div className="form-group">
          <label>Guardian Phone</label>
          <input
            type="tel"
            name="guardian_phone"
            value={formData.guardian_phone}
            onChange={handleChange}
          />
        </div>
        
        <div className="form-group">
          <label>Guardian Email</label>
          <input
            type="email"
            name="guardian_email"
            value={formData.guardian_email}
            onChange={handleChange}
          />
        </div>
        
        <div className="form-group">
          <label>Address</label>
          <textarea
            name="address"
            value={formData.address}
            onChange={handleChange}
            rows="3"
          ></textarea>
        </div>
        
        <button type="submit" className="btn btn-primary" disabled={loading}>
          {loading ? 'Creating...' : 'Create Student'}
        </button>
      </form>
    </div>
  );
}

export default StudentForm;