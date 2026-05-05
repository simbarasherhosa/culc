import React, { useState, useEffect } from 'react';

function ExchangeRates({ token }) {
  const [rates, setRates] = useState([]);
  const [currentRate, setCurrentRate] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({
    rate: '',
    effective_date: '',
    notes: ''
  });

  useEffect(() => {
    fetchRates();
  }, []);

  const fetchRates = async () => {
    try {
      const [ratesRes, currentRes] = await Promise.all([
        fetch('http://localhost:5001/api/v1/exchange-rates', { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch('http://localhost:5001/api/v1/exchange-rates/current', { headers: { 'Authorization': `Bearer ${token}` } })
      ]);
      
      setRates(await ratesRes.json());
      setCurrentRate(await currentRes.json());
    } catch (error) {
      console.error('Error fetching rates:', error);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('http://localhost:5001/api/v1/exchange-rates', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(formData)
      });
      
      if (response.ok) {
        alert('Exchange rate set successfully!');
        setShowForm(false);
        fetchRates();
        setFormData({
          rate: '',
          effective_date: '',
          notes: ''
        });
      } else {
        const error = await response.json();
        alert(error.error || 'Failed to set exchange rate');
      }
    } catch (error) {
      console.error('Error:', error);
      alert('Error setting exchange rate');
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h2>💱 Exchange Rate Management</h2>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? 'Cancel' : '+ Set Rate'}
        </button>
      </div>

      {currentRate && (
        <div className="card" style={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', color: 'white' }}>
          <h3>Current Exchange Rate</h3>
          <div style={{ fontSize: '2rem', fontWeight: 'bold' }}>
            1 USD = {currentRate.rate} ZWG
          </div>
          <small>Effective: {new Date(currentRate.effective_date).toLocaleDateString()}</small>
          {currentRate.notes && <div><small>Note: {currentRate.notes}</small></div>}
        </div>
      )}

      {showForm && (
        <div className="card">
          <h3>Set New Exchange Rate</h3>
          <form onSubmit={handleSubmit}>
            <div className="form-row">
              <div className="form-group">
                <label>Exchange Rate (USD to ZWG) *</label>
                <input
                  type="number"
                  step="0.001"
                  value={formData.rate}
                  onChange={(e) => setFormData({...formData, rate: e.target.value})}
                  placeholder="e.g., 0.035"
                  required
                />
                <small>Example: 1 ZWG = 0.035 USD</small>
              </div>
              
              <div className="form-group">
                <label>Effective Date *</label>
                <input
                  type="date"
                  value={formData.effective_date}
                  onChange={(e) => setFormData({...formData, effective_date: e.target.value})}
                  required
                />
              </div>
            </div>

            <div className="form-group">
              <label>Notes</label>
              <textarea
                value={formData.notes}
                onChange={(e) => setFormData({...formData, notes: e.target.value})}
                rows="2"
                placeholder="Reason for rate change (optional)"
              />
            </div>

            <button type="submit" className="btn btn-primary">Set Rate</button>
          </form>
        </div>
      )}

      <div className="card">
        <h3>Rate History</h3>
        {rates.length === 0 ? (
          <p>No exchange rates recorded yet.</p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table>
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Rate (USD to ZWG)</th>
                  <th>Notes</th>
                </tr>
              </thead>
              <tbody>
                {rates.map(rate => (
                  <tr key={rate.id}>
                    <td>{new Date(rate.effective_date).toLocaleDateString()}</td>
                    <td><strong>{rate.rate}</strong></td>
                    <td>{rate.notes || '-'}</td>
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

export default ExchangeRates;