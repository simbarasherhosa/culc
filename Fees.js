import React, { useState, useEffect } from 'react';

function Fees({ token }) {
  const [students, setStudents] = useState([]);
  const [fees, setFees] = useState([]);
  const [terms, setTerms] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({
    student_id: '',
    term_id: '',
    amount: '',
    currency: 'USD',
    fee_type: 'tuition',
    due_date: ''
  });

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [studentsRes, feesRes, termsRes] = await Promise.all([
        fetch('http://localhost:5000/api/v1/students', { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch('http://localhost:5000/api/v1/fees', { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch('http://localhost:5000/api/v1/terms', { headers: { 'Authorization': `Bearer ${token}` } })
      ]);
      
      setStudents(await studentsRes.json());
      setFees(await feesRes.json());
      setTerms(await termsRes.json());
    } catch (error) {
      console.error('Error fetching data:', error);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      // Get current exchange rate
      const rateResponse = await fetch('http://localhost:5000/api/v1/exchange-rates/current', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const rateData = await rateResponse.json();
      
      const submitData = {
        ...formData,
        rate_of_day: rateData.rate || 1.0
      };
      
      const response = await fetch('http://localhost:5000/api/v1/fees', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(submitData)
      });
      
      if (response.ok) {
        alert('Fee invoice created successfully!');
        setShowForm(false);
        fetchData();
        setFormData({
          student_id: '',
          term_id: '',
          amount: '',
          currency: 'USD',
          fee_type: 'tuition',
          due_date: ''
        });
      } else {
        const error = await response.json();
        alert(error.error || 'Failed to create fee invoice');
      }
    } catch (error) {
      console.error('Error:', error);
      alert('Error creating fee invoice');
    }
  };

  const getStatusBadge = (status, dueDate) => {
    if (status === 'paid') return <span className="badge badge-success">Paid</span>;
    if (status === 'partial') return <span className="badge badge-warning">Partial</span>;
    if (new Date(dueDate) < new Date() && status !== 'paid') {
      return <span className="badge badge-danger">Overdue</span>;
    }
    return <span className="badge badge-info">Pending</span>;
  };

  const feeTypes = ['tuition', 'sports', 'development', 'exam', 'uniform', 'transport', 'other'];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h2>💰 Fee Management</h2>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? 'Cancel' : '+ Create Invoice'}
        </button>
      </div>

      {showForm && (
        <div className="card">
          <h3>Create Fee Invoice</h3>
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
                  {students.map(s => <option key={s.id} value={s.id}>{s.full_name} ({s.class_name})</option>)}
                </select>
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

            <div className="form-row">
              <div className="form-group">
                <label>Amount *</label>
                <input
                  type="number"
                  step="0.01"
                  value={formData.amount}
                  onChange={(e) => setFormData({...formData, amount: e.target.value})}
                  required
                />
              </div>
              
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
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Fee Type *</label>
                <select
                  value={formData.fee_type}
                  onChange={(e) => setFormData({...formData, fee_type: e.target.value})}
                >
                  {feeTypes.map(type => <option key={type} value={type}>{type.toUpperCase()}</option>)}
                </select>
              </div>
              
              <div className="form-group">
                <label>Due Date *</label>
                <input
                  type="date"
                  value={formData.due_date}
                  onChange={(e) => setFormData({...formData, due_date: e.target.value})}
                  required
                />
              </div>
            </div>

            <button type="submit" className="btn btn-primary">Create Invoice</button>
          </form>
        </div>
      )}

      <div className="card">
        <h3>All Fee Invoices</h3>
        {fees.length === 0 ? (
          <p>No fee invoices found. Create your first invoice above.</p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table>
              <thead>
                <tr>
                  <th>Student</th>
                  <th>Term</th>
                  <th>Amount</th>
                  <th>Currency</th>
                  <th>Fee Type</th>
                  <th>Due Date</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {fees.map(fee => (
                  <tr key={fee.id}>
                    <td>{fee.student_name}</td>
                    <td>Term {fee.term}</td>
                    <td>{fee.amount}</td>
                    <td>{fee.currency}</td>
                    <td>{fee.fee_type?.toUpperCase()}</td>
                    <td>{new Date(fee.due_date).toLocaleDateString()}</td>
                    <td>{getStatusBadge(fee.status, fee.due_date)}</td>
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

export default Fees;