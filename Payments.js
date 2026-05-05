// import React, { useState, useEffect } from 'react';

// function Payments({ token }) {
//   const [students, setStudents] = useState([]);
//   const [payments, setPayments] = useState([]);
//   const [showForm, setShowForm] = useState(false);
//   const [formData, setFormData] = useState({
//     student_id: '',
//     amount: '',
//     currency: 'USD',
//     payment_method: 'cash',
//     transaction_reference: '',
//     notes: ''
//   });

//   useEffect(() => {
//     fetchData();
//   }, []);

//   const fetchData = async () => {
//     try {
//       const [studentsRes, paymentsRes] = await Promise.all([
//         fetch('http://localhost:5000/api/v1/students', { headers: { 'Authorization': `Bearer ${token}` } }),
//         fetch('http://localhost:5000/api/v1/fees', { headers: { 'Authorization': `Bearer ${token}` } })
//       ]);
      
//       setStudents(await studentsRes.json());
//       setPayments(await paymentsRes.json());
//     } catch (error) {
//       console.error('Error fetching data:', error);
//     }
//   };

//   const handleSubmit = async (e) => {
//     e.preventDefault();
//     try {
//       // Get current exchange rate
//       const rateResponse = await fetch('http://localhost:5000/api/v1/exchange-rates/current', {
//         headers: { 'Authorization': `Bearer ${token}` }
//       });
//       const rateData = await rateResponse.json();
      
//       const submitData = {
//         ...formData,
//         rate_of_day: rateData.rate || 1.0
//       };
      
//       const response = await fetch('http://localhost:5000/api/v1/payments', {
//         method: 'POST',
//         headers: {
//           'Content-Type': 'application/json',
//           'Authorization': `Bearer ${token}`
//         },
//         body: JSON.stringify(submitData)
//       });
      
//       if (response.ok) {
//         const payment = await response.json();
//         alert(`Payment recorded! Receipt #: ${payment.receipt_number}`);
//         setShowForm(false);
//         fetchData();
//         setFormData({
//           student_id: '',
//           amount: '',
//           currency: 'USD',
//           payment_method: 'cash',
//           transaction_reference: '',
//           notes: ''
//         });
//       } else {
//         const error = await response.json();
//         alert(error.error || 'Failed to record payment');
//       }
//     } catch (error) {
//       console.error('Error:', error);
//       alert('Error recording payment');
//     }
//   };

//   const paymentMethods = ['cash', 'ecocash', 'onemoney', 'bank_transfer', 'card'];

//   return (
//     <div>
//       <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
//         <h2>💳 Payment Processing</h2>
//         <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
//           {showForm ? 'Cancel' : '+ Record Payment'}
//         </button>
//       </div>

//       {showForm && (
//         <div className="card">
//           <h3>Record Payment</h3>
//           <form onSubmit={handleSubmit}>
//             <div className="form-row">
//               <div className="form-group">
//                 <label>Student *</label>
//                 <select
//                   value={formData.student_id}
//                   onChange={(e) => setFormData({...formData, student_id: e.target.value})}
//                   required
//                 >
//                   <option value="">Select Student</option>
//                   {students.map(s => <option key={s.id} value={s.id}>{s.full_name}</option>)}
//                 </select>
//               </div>
              
//               <div className="form-group">
//                 <label>Amount *</label>
//                 <input
//                   type="number"
//                   step="0.01"
//                   value={formData.amount}
//                   onChange={(e) => setFormData({...formData, amount: e.target.value})}
//                   required
//                 />
//               </div>
//             </div>

//             <div className="form-row">
//               <div className="form-group">
//                 <label>Currency *</label>
//                 <select
//                   value={formData.currency}
//                   onChange={(e) => setFormData({...formData, currency: e.target.value})}
//                 >
//                   <option value="USD">USD</option>
//                   <option value="ZWG">ZWG</option>
//                 </select>
//               </div>
              
//               <div className="form-group">
//                 <label>Payment Method *</label>
//                 <select
//                   value={formData.payment_method}
//                   onChange={(e) => setFormData({...formData, payment_method: e.target.value})}
//                 >
//                   {paymentMethods.map(method => <option key={method} value={method}>{method.toUpperCase()}</option>)}
//                 </select>
//               </div>
//             </div>

//             <div className="form-group">
//               <label>Transaction Reference (For EcoCash/OneMoney)</label>
//               <input
//                 type="text"
//                 value={formData.transaction_reference}
//                 onChange={(e) => setFormData({...formData, transaction_reference: e.target.value})}
//                 placeholder="EcoCash transaction ID"
//               />
//             </div>

//             <div className="form-group">
//               <label>Notes</label>
//               <textarea
//                 value={formData.notes}
//                 onChange={(e) => setFormData({...formData, notes: e.target.value})}
//                 rows="2"
//                 placeholder="Additional notes"
//               />
//             </div>

//             <button type="submit" className="btn btn-primary">Record Payment</button>
//           </form>
//         </div>
//       )}

//       <div className="card">
//         <h3>Recent Payments</h3>
//         {payments.length === 0 ? (
//           <p>No payments recorded yet.</p>
//         ) : (
//           <div style={{ overflowX: 'auto' }}>
//             <table>
//               <thead>
//                 <tr>
//                   <th>Receipt #</th>
//                   <th>Student</th>
//                   <th>Amount</th>
//                   <th>Currency</th>
//                   <th>Payment Method</th>
//                   <th>Date</th>
//                   <th>Transaction Ref</th>
//                 </tr>
//               </thead>
//               <tbody>
//                 {payments.map(payment => (
//                   <tr key={payment.id}>
//                     <td><strong>{payment.receipt_number}</strong></td>
//                     <td>{payment.student_name}</td>
//                     <td>{payment.amount}</td>
//                     <td>{payment.currency}</td>
//                     <td>{payment.payment_method?.toUpperCase()}</td>
//                     <td>{new Date(payment.payment_date).toLocaleDateString()}</td>
//                     <td>{payment.transaction_reference || '-'}</td>
//                   </tr>
//                 ))}
//               </tbody>
//             </table>
//           </div>
//         )}
//       </div>
//     </div>
//   );
// }

// export default Payments;



import React, { useState, useEffect } from 'react';

function Payments({ token }) {
  const [students, setStudents] = useState([]);
  const [payments, setPayments] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [loading, setLoading] = useState(true);
  const [formData, setFormData] = useState({
    student_id: '',
    amount: '',
    currency: 'USD',
    payment_method: 'cash',
    transaction_reference: '',
    notes: ''
  });

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [studentsRes, paymentsRes] = await Promise.all([
        fetch('http://localhost:5001/api/v1/students', { 
          headers: { 'Authorization': `Bearer ${token}` } 
        }),
        fetch('http://localhost:5001/api/v1/payments', { 
          headers: { 'Authorization': `Bearer ${token}` } 
        })
      ]);
      
      if (studentsRes.ok) {
        const studentsData = await studentsRes.json();
        setStudents(studentsData);
      } else {
        console.error('Failed to fetch students');
      }
      
      if (paymentsRes.ok) {
        const paymentsData = await paymentsRes.json();
        console.log('Payments data:', paymentsData); // Debug log
        setPayments(paymentsData);
      } else {
        console.error('Failed to fetch payments');
      }
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      // Get current exchange rate
      const rateResponse = await fetch('http://localhost:5001/api/v1/exchange-rates/current', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const rateData = await rateResponse.json();
      
      const submitData = {
        ...formData,
        amount: parseFloat(formData.amount), // Ensure amount is a number
        rate_of_day: rateData.rate || 1.0
      };
      
      const response = await fetch('http://localhost:5001/api/v1/payments', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(submitData)
      });
      
      if (response.ok) {
        const payment = await response.json();
        alert(`Payment recorded! Receipt #: ${payment.receipt_number}`);
        setShowForm(false);
        fetchData(); // Refresh the payments list
        setFormData({
          student_id: '',
          amount: '',
          currency: 'USD',
          payment_method: 'cash',
          transaction_reference: '',
          notes: ''
        });
      } else {
        const error = await response.json();
        alert(error.error || 'Failed to record payment');
      }
    } catch (error) {
      console.error('Error:', error);
      alert('Error recording payment');
    }
  };

  // Format date safely
  const formatDate = (dateString) => {
    if (!dateString) return 'No date';
    try {
      const date = new Date(dateString);
      if (isNaN(date.getTime())) return 'Invalid date';
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch (error) {
      console.error('Date parsing error:', error);
      return 'Invalid date';
    }
  };

  const paymentMethods = ['cash', 'ecocash', 'onemoney', 'bank_transfer', 'card'];

  if (loading) return <div className="loading">Loading payments...</div>;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h2>💳 Payment Processing</h2>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? 'Cancel' : '+ Record Payment'}
        </button>
      </div>

      {showForm && (
        <div className="card">
          <h3>Record Payment</h3>
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
                <label>Amount *</label>
                <input
                  type="number"
                  step="0.01"
                  value={formData.amount}
                  onChange={(e) => setFormData({...formData, amount: e.target.value})}
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
                <label>Payment Method *</label>
                <select
                  value={formData.payment_method}
                  onChange={(e) => setFormData({...formData, payment_method: e.target.value})}
                >
                  {paymentMethods.map(method => <option key={method} value={method}>{method.toUpperCase()}</option>)}
                </select>
              </div>
            </div>

            <div className="form-group">
              <label>Transaction Reference (For EcoCash/OneMoney)</label>
              <input
                type="text"
                value={formData.transaction_reference}
                onChange={(e) => setFormData({...formData, transaction_reference: e.target.value})}
                placeholder="EcoCash transaction ID"
              />
            </div>

            <div className="form-group">
              <label>Notes</label>
              <textarea
                value={formData.notes}
                onChange={(e) => setFormData({...formData, notes: e.target.value})}
                rows="2"
                placeholder="Additional notes"
              />
            </div>

            <button type="submit" className="btn btn-primary">Record Payment</button>
          </form>
        </div>
      )}

      <div className="card">
        <h3>Recent Payments</h3>
        {payments.length === 0 ? (
          <p>No payments recorded yet.</p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="payments-table">
              <thead>
                <tr>
                  <th>Receipt #</th>
                  <th>Student</th>
                  <th>Amount</th>
                  <th>Currency</th>
                  <th>Payment Method</th>
                  <th>Date</th>
                  <th>Transaction Ref</th>
                </tr>
              </thead>
              <tbody>
                {payments.map(payment => (
                  <tr key={payment.id}>
                    <td>
                      <strong>{payment.receipt_number || 'N/A'}</strong>
                    </td>
                    <td>{payment.student_name || `Student ID: ${payment.student_id}`}</td>
                    <td>
                      {payment.currency === 'USD' ? '$' : 'ZWG '}
                      {typeof payment.amount === 'number' ? payment.amount.toFixed(2) : payment.amount}
                    </td>
                    <td>{payment.currency}</td>
                    <td>
                      <span className={`badge badge-${payment.payment_method}`}>
                        {payment.payment_method?.toUpperCase() || 'N/A'}
                      </span>
                    </td>
                    <td>{formatDate(payment.payment_date)}</td>
                    <td>{payment.transaction_reference || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add some basic styling */}
      <style jsx>{`
        .badge-cash { background: #28a745; color: white; padding: 3px 8px; border-radius: 3px; }
        .badge-ecocash { background: #17a2b8; color: white; padding: 3px 8px; border-radius: 3px; }
        .badge-onemoney { background: #ffc107; color: black; padding: 3px 8px; border-radius: 3px; }
        .badge-bank_transfer { background: #6c757d; color: white; padding: 3px 8px; border-radius: 3px; }
        .badge-card { background: #007bff; color: white; padding: 3px 8px; border-radius: 3px; }
        .payments-table {
          width: 100%;
          border-collapse: collapse;
        }
        .payments-table th,
        .payments-table td {
          padding: 12px;
          text-align: left;
          border-bottom: 1px solid #ddd;
        }
        .payments-table th {
          background-color: #f2f2f2;
          font-weight: bold;
        }
        .payments-table tr:hover {
          background-color: #f5f5f5;
        }
      `}</style>
    </div>
  );
}

export default Payments;