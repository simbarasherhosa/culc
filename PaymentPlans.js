import React, { useState, useEffect } from 'react';

function PaymentPlans({ token }) {
  const [students, setStudents] = useState([]);
  const [plans, setPlans] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [formData, setFormData] = useState({
    student_id: '',
    total_amount: '',
    currency: 'USD',
    installment_amount: '',
    number_of_installments: '',
    start_date: ''
  });

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    setError('');
    try {
      // First fetch all students
      const studentsRes = await fetch('http://localhost:5001/api/v1/students', { 
        headers: { 'Authorization': `Bearer ${token}` } 
      });
      
      if (!studentsRes.ok) {
        throw new Error('Failed to fetch students');
      }
      
      const studentsData = await studentsRes.json();
      setStudents(studentsData);
      
      // Then fetch payment plans for all students
      const allPlans = [];
      for (const student of studentsData) {
        try {
          const plansRes = await fetch(`http://localhost:5001/api/v1/students/${student.id}/payment-plans`, {
            headers: { 'Authorization': `Bearer ${token}` }
          });
          
          if (plansRes.ok) {
            const studentPlans = await plansRes.json();
            allPlans.push(...studentPlans);
          }
        } catch (err) {
          console.error(`Error fetching plans for student ${student.id}:`, err);
        }
      }
      
      setPlans(allPlans);
    } catch (error) {
      console.error('Error fetching data:', error);
      setError('Failed to load payment plans. Please refresh the page.');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    // Validate form data
    if (parseFloat(formData.total_amount) <= 0) {
      setError('Total amount must be greater than 0');
      return;
    }
    
    if (parseFloat(formData.installment_amount) <= 0) {
      setError('Installment amount must be greater than 0');
      return;
    }
    
    if (parseInt(formData.number_of_installments) <= 0) {
      setError('Number of installments must be greater than 0');
      return;
    }
    
    if (!formData.start_date) {
      setError('Start date is required');
      return;
    }
    
    try {
      const submitData = {
        student_id: parseInt(formData.student_id, 10),
        total_amount: parseFloat(formData.total_amount),
        currency: formData.currency,
        installment_amount: parseFloat(formData.installment_amount),
        number_of_installments: parseInt(formData.number_of_installments, 10),
        start_date: formData.start_date
      };
      
      console.log('Submitting payment plan:', submitData);
      
      const response = await fetch('http://localhost:5001/api/v1/payment-plans', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(submitData)
      });
      
      const data = await response.json();
      
      if (response.ok) {
        alert('Payment plan created successfully!');
        setShowForm(false);
        // Reset form
        setFormData({
          student_id: '',
          total_amount: '',
          currency: 'USD',
          installment_amount: '',
          number_of_installments: '',
          start_date: ''
        });
        // Refresh the plans list
        await fetchData();
      } else {
        setError(data.error || 'Failed to create payment plan');
        console.error('Server error:', data);
      }
    } catch (error) {
      console.error('Error:', error);
      setError('Error creating payment plan. Please check your connection.');
    }
  };

  const getStatusBadge = (status) => {
    switch(status) {
      case 'active': return <span className="badge badge-success">Active</span>;
      case 'completed': return <span className="badge badge-info">Completed</span>;
      case 'defaulted': return <span className="badge badge-danger">Defaulted</span>;
      default: return <span className="badge badge-warning">{status}</span>;
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    try {
      const date = new Date(dateString);
      if (isNaN(date.getTime())) return 'Invalid date';
      return date.toLocaleDateString();
    } catch (error) {
      return 'Invalid date';
    }
  };

  if (loading) return <div className="loading">Loading payment plans...</div>;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h2>📋 Payment Plans</h2>
        <button className="btn btn-primary" onClick={() => {
          setShowForm(!showForm);
          setError('');
        }}>
          {showForm ? 'Cancel' : '+ Create Plan'}
        </button>
      </div>

      {error && (
        <div style={{ backgroundColor: '#f8d7da', color: '#721c24', padding: '10px', borderRadius: '5px', marginBottom: '1rem' }}>
          ❌ {error}
        </div>
      )}

      {showForm && (
        <div className="card">
          <h3>Create Payment Plan</h3>
          <form onSubmit={handleSubmit}>
            <div className="form-row">
              <div className="form-group">
                <label>Student *</label>
                <select
                  value={formData.student_id}
                  onChange={(e) => setFormData({...formData, student_id: e.target.value})}
                  required
                >
                  <option value="">Select Student</option>
                  {students.map(s => <option key={s.id} value={s.id}>{s.full_name}</option>)}
                </select>
              </div>
              
              <div className="form-group">
                <label>Total Amount *</label>
                <input
                  type="number"
                  step="0.01"
                  min="0"
                  value={formData.total_amount}
                  onChange={(e) => setFormData({...formData, total_amount: e.target.value})}
                  required
                />
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Currency *</label>
                <select
                  value={formData.currency}
                  onChange={(e) => setFormData({...formData, currency: e.target.value})}
                >
                  <option value="USD">USD</option>
                  <option value="ZWG">ZWG</option>
                </select>
              </div>
              
              <div className="form-group">
                <label>Installment Amount *</label>
                <input
                  type="number"
                  step="0.01"
                  min="0"
                  value={formData.installment_amount}
                  onChange={(e) => setFormData({...formData, installment_amount: e.target.value})}
                  required
                />
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Number of Installments *</label>
                <input
                  type="number"
                  min="1"
                  max="24"
                  value={formData.number_of_installments}
                  onChange={(e) => setFormData({...formData, number_of_installments: e.target.value})}
                  required
                />
              </div>
              
              <div className="form-group">
                <label>Start Date *</label>
                <input
                  type="date"
                  value={formData.start_date}
                  onChange={(e) => setFormData({...formData, start_date: e.target.value})}
                  required
                />
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <button type="submit" className="btn btn-primary">Create Plan</button>
              <button type="button" className="btn btn-secondary" onClick={() => setShowForm(false)}>
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="card">
        <h3>Active Payment Plans</h3>
        {plans.length === 0 ? (
          <p>No payment plans created yet.</p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="plans-table">
              <thead>
                <tr>
                  <th>Student</th>
                  <th>Total Amount</th>
                  <th>Installment</th>
                  <th># Payments</th>
                  <th>Start Date</th>
                  <th>End Date</th>
                  <th>Next Payment</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {plans.map(plan => (
                  <tr key={plan.id}>
                    <td>{plan.student_name || `Student ID: ${plan.student_id}`}</td>
                    <td>{typeof plan.total_amount === 'number' ? plan.total_amount.toFixed(2) : plan.total_amount} {plan.currency}</td>
                    <td>{typeof plan.installment_amount === 'number' ? plan.installment_amount.toFixed(2) : plan.installment_amount} {plan.currency}</td>
                    <td>{plan.number_of_installments}</td>
                    <td>{formatDate(plan.start_date)}</td>
                    <td>{formatDate(plan.end_date)}</td>
                    <td>{formatDate(plan.next_payment_date)}</td>
                    <td>{getStatusBadge(plan.status)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <style jsx>{`
        .badge-success {
          background-color: #28a745;
          color: white;
          padding: 3px 8px;
          border-radius: 3px;
          font-size: 12px;
        }
        .badge-info {
          background-color: #17a2b8;
          color: white;
          padding: 3px 8px;
          border-radius: 3px;
          font-size: 12px;
        }
        .badge-danger {
          background-color: #dc3545;
          color: white;
          padding: 3px 8px;
          border-radius: 3px;
          font-size: 12px;
        }
        .badge-warning {
          background-color: #ffc107;
          color: black;
          padding: 3px 8px;
          border-radius: 3px;
          font-size: 12px;
        }
        .plans-table {
          width: 100%;
          border-collapse: collapse;
        }
        .plans-table th,
        .plans-table td {
          padding: 12px;
          text-align: left;
          border-bottom: 1px solid #ddd;
        }
        .plans-table th {
          background-color: #f2f2f2;
          font-weight: bold;
        }
        .plans-table tr:hover {
          background-color: #f5f5f5;
        }
        .loading {
          text-align: center;
          padding: 20px;
          font-size: 16px;
          color: #666;
        }
      `}</style>
    </div>
  );
}

export default PaymentPlans;