import React, { useState, useEffect } from 'react';

function Clubs({ token }) {
  const [clubs, setClubs] = useState([]);
  const [students, setStudents] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [showRegister, setShowRegister] = useState(false);
  const [showMembers, setShowMembers] = useState(false);
  const [selectedClub, setSelectedClub] = useState(null);
  const [selectedClubForMembers, setSelectedClubForMembers] = useState(null);
  const [clubMembers, setClubMembers] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    category: '',
    patron_name: '',
    meeting_day: '',
    meeting_time: '',
    venue: '',
    description: ''
  });
  const [registerData, setRegisterData] = useState({
    student_id: '',
    role: 'member'
  });

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [clubsRes, studentsRes] = await Promise.all([
        fetch('http://localhost:5001/api/v1/clubs', { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch('http://localhost:5001/api/v1/students', { headers: { 'Authorization': `Bearer ${token}` } })
      ]);
      
      const clubsData = await clubsRes.json();
      const studentsData = await studentsRes.json();
      
      setClubs(clubsData);
      setStudents(studentsData);
    } catch (error) {
      console.error('Error fetching data:', error);
      alert('Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const fetchClubMembers = async (clubId) => {
    setLoading(true);
    try {
      const response = await fetch(`http://localhost:5001/api/v1/clubs/${clubId}/members`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      setClubMembers(data);
    } catch (error) {
      console.error('Error fetching members:', error);
      alert('Failed to load club members');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('http://localhost:5001/api/v1/clubs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(formData)
      });
      
      if (response.ok) {
        alert('Club created successfully!');
        setShowForm(false);
        fetchData();
        setFormData({
          name: '',
          category: '',
          patron_name: '',
          meeting_day: '',
          meeting_time: '',
          venue: '',
          description: ''
        });
      } else {
        const error = await response.json();
        alert(error.error || 'Failed to create club');
      }
    } catch (error) {
      console.error('Error:', error);
      alert('Error creating club');
    }
  };

  const handleRegister = async (e, clubId) => {
    e.preventDefault();
    if (!registerData.student_id) {
      alert('Please select a student');
      return;
    }
    
    try {
      const response = await fetch(`http://localhost:5001/api/v1/clubs/${clubId}/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(registerData)
      });
      
      if (response.ok) {
        alert('Student registered successfully!');
        setShowRegister(false);
        setSelectedClub(null);
        setRegisterData({ student_id: '', role: 'member' });
        setSearchTerm('');
        // Refresh members if members modal is open
        if (showMembers && selectedClubForMembers) {
          fetchClubMembers(selectedClubForMembers.id);
        }
      } else {
        const error = await response.json();
        alert(error.error || 'Failed to register student');
      }
    } catch (error) {
      console.error('Error:', error);
      alert('Error registering student');
    }
  };

  const handleRemoveMember = async (clubId, studentId, studentName) => {
    if (!window.confirm(`Remove ${studentName} from this club?`)) return;
    
    try {
      const response = await fetch(`http://localhost:5001/api/v1/clubs/${clubId}/members/${studentId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (response.ok) {
        alert('Member removed successfully');
        // Refresh members list
        fetchClubMembers(clubId);
        fetchData(); // Refresh club list to update member counts
      } else {
        const error = await response.json();
        alert(error.error || 'Failed to remove member');
      }
    } catch (error) {
      console.error('Error:', error);
      alert('Error removing member');
    }
  };

  const handleViewMembers = async (club) => {
    setSelectedClubForMembers(club);
    await fetchClubMembers(club.id);
    setShowMembers(true);
  };

  const handleRegisterClick = (club) => {
    setSelectedClub(club);
    setShowRegister(true);
    setSearchTerm('');
  };

  const closeRegisterModal = () => {
    setShowRegister(false);
    setSelectedClub(null);
    setSearchTerm('');
  };

  const closeMembersModal = () => {
    setShowMembers(false);
    setSelectedClubForMembers(null);
    setClubMembers([]);
  };

  // Filter students based on search term
  const filteredStudents = students.filter(student => 
    student.full_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (student.class_name && student.class_name.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const categories = ['academic', 'cultural', 'religious', 'sports', 'arts', 'technology', 'community'];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h2>🎯 Clubs & Societies</h2>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? 'Cancel' : '+ Create Club'}
        </button>
      </div>

      {showForm && (
        <div className="card">
          <h3>Create New Club</h3>
          <form onSubmit={handleSubmit}>
            <div className="form-row">
              <div className="form-group">
                <label>Club Name *</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({...formData, name: e.target.value})}
                  required
                />
              </div>
              
              <div className="form-group">
                <label>Category</label>
                <select
                  value={formData.category}
                  onChange={(e) => setFormData({...formData, category: e.target.value})}
                >
                  <option value="">Select Category</option>
                  {categories.map(c => <option key={c} value={c}>{c.toUpperCase()}</option>)}
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Patron/Teacher</label>
                <input
                  type="text"
                  value={formData.patron_name}
                  onChange={(e) => setFormData({...formData, patron_name: e.target.value})}
                />
              </div>
              
              <div className="form-group">
                <label>Meeting Day</label>
                <select
                  value={formData.meeting_day}
                  onChange={(e) => setFormData({...formData, meeting_day: e.target.value})}
                >
                  <option value="">Select Day</option>
                  <option value="Monday">Monday</option>
                  <option value="Tuesday">Tuesday</option>
                  <option value="Wednesday">Wednesday</option>
                  <option value="Thursday">Thursday</option>
                  <option value="Friday">Friday</option>
                  <option value="Saturday">Saturday</option>
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Meeting Time</label>
                <input
                  type="time"
                  value={formData.meeting_time}
                  onChange={(e) => setFormData({...formData, meeting_time: e.target.value})}
                />
              </div>
              
              <div className="form-group">
                <label>Venue</label>
                <input
                  type="text"
                  value={formData.venue}
                  onChange={(e) => setFormData({...formData, venue: e.target.value})}
                />
              </div>
            </div>

            <div className="form-group">
              <label>Description</label>
              <textarea
                value={formData.description}
                onChange={(e) => setFormData({...formData, description: e.target.value})}
                rows="3"
              />
            </div>

            <button type="submit" className="btn btn-primary">Create Club</button>
          </form>
        </div>
      )}

      <div className="card">
        <h3>All Clubs</h3>
        {loading && <div className="loading">Loading...</div>}
        {!loading && clubs.length === 0 ? (
          <p>No clubs created yet. Create your first club above.</p>
        ) : (
          <div className="stats-grid">
            {clubs.map(club => (
              <div key={club.id} className="stat-card" style={{ textAlign: 'left' }}>
                <h3>
                  {club.name}
                  {club.category && <span className="badge" style={{ marginLeft: '10px', fontSize: '12px' }}>{club.category}</span>}
                </h3>
                {club.patron_name && <p><strong>Patron:</strong> {club.patron_name}</p>}
                {club.meeting_day && <p><strong>Meeting:</strong> {club.meeting_day} at {club.meeting_time}</p>}
                {club.venue && <p><strong>Venue:</strong> {club.venue}</p>}
                {club.description && <p><small>{club.description}</small></p>}
                
                <div style={{ display: 'flex', gap: '10px', marginTop: '1rem' }}>
                  <button 
                    className="btn btn-primary" 
                    style={{ flex: 1 }}
                    onClick={() => handleRegisterClick(club)}
                  >
                    Register Student
                  </button>
                  <button 
                    className="btn btn-secondary" 
                    style={{ flex: 1 }}
                    onClick={() => handleViewMembers(club)}
                  >
                    View Members
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Modal for Registering Students */}
      {showRegister && selectedClub && (
        <div className="modal" onClick={closeRegisterModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '500px' }}>
            <div className="modal-header">
              <h3>Register Student for {selectedClub.name}</h3>
              <button className="close-btn" onClick={closeRegisterModal}>×</button>
            </div>
            <form onSubmit={(e) => handleRegister(e, selectedClub.id)}>
              <div className="form-group">
                <label>Search Student *</label>
                <input
                  type="text"
                  placeholder="Type to search student name or class..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="form-control"
                  autoFocus
                />
              </div>
              
              <div className="form-group">
                <label>Select Student *</label>
                <select
                  value={registerData.student_id}
                  onChange={(e) => setRegisterData({...registerData, student_id: e.target.value})}
                  required
                  size="5"
                  style={{ height: 'auto', minHeight: '150px' }}
                >
                  <option value="">Choose a student...</option>
                  {filteredStudents.map(s => (
                    <option key={s.id} value={s.id}>
                      {s.full_name} - {s.class_name || 'No Class'}
                    </option>
                  ))}
                </select>
                {filteredStudents.length === 0 && searchTerm && (
                  <small style={{ color: '#999' }}>No students found matching "{searchTerm}"</small>
                )}
              </div>
              
              <div className="form-group">
                <label>Role</label>
                <select
                  value={registerData.role}
                  onChange={(e) => setRegisterData({...registerData, role: e.target.value})}
                >
                  <option value="member">Member</option>
                  <option value="chairperson">Chairperson</option>
                  <option value="secretary">Secretary</option>
                  <option value="treasurer">Treasurer</option>
                </select>
              </div>
              
              <div style={{ display: 'flex', gap: '10px', marginTop: '1rem' }}>
                <button type="submit" className="btn btn-primary">Register</button>
                <button type="button" className="btn btn-secondary" onClick={closeRegisterModal}>
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal for Viewing Members */}
      {showMembers && selectedClubForMembers && (
        <div className="modal" onClick={closeMembersModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '700px' }}>
            <div className="modal-header">
              <h3>{selectedClubForMembers.name} - Members ({clubMembers.length})</h3>
              <button className="close-btn" onClick={closeMembersModal}>×</button>
            </div>
            <div className="modal-body">
              {loading ? (
                <div className="loading">Loading members...</div>
              ) : clubMembers.length === 0 ? (
                <p>No members registered yet.</p>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table className="members-table">
                    <thead>
                      <tr>
                        <th>Student Name</th>
                        <th>Role</th>
                        <th>Join Date</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {clubMembers.map(member => (
                        <tr key={member.id}>
                          <td>{member.student_name}</td>
                          <td>
                            <span className={`badge badge-${member.role}`}>
                              {member.role?.toUpperCase() || 'MEMBER'}
                            </span>
                          </td>
                          <td>{new Date(member.join_date).toLocaleDateString()}</td>
                          <td>
                            <button
                              className="btn btn-danger btn-sm"
                              onClick={() => handleRemoveMember(selectedClubForMembers.id, member.student_id, member.student_name)}
                              style={{ padding: '5px 10px', fontSize: '12px' }}
                            >
                              Remove
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
            <div className="modal-footer" style={{ marginTop: '1rem', textAlign: 'right' }}>
              <button className="btn btn-secondary" onClick={closeMembersModal}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      <style jsx>{`
        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
          gap: 1rem;
        }
        .stat-card {
          background: white;
          border-radius: 8px;
          padding: 1rem;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .modal {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0,0,0,0.5);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 1000;
        }
        .modal-content {
          background: white;
          border-radius: 8px;
          padding: 1.5rem;
          max-width: 90%;
          max-height: 90%;
          overflow: auto;
        }
        .modal-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 1rem;
          padding-bottom: 0.5rem;
          border-bottom: 1px solid #ddd;
        }
        .close-btn {
          background: none;
          border: none;
          font-size: 24px;
          cursor: pointer;
          color: #999;
        }
        .close-btn:hover {
          color: #333;
        }
        .form-control {
          width: 100%;
          padding: 8px;
          border: 1px solid #ddd;
          border-radius: 4px;
        }
        select[size] {
          overflow-y: auto;
        }
        .badge {
          padding: 3px 8px;
          border-radius: 3px;
          font-size: 11px;
          font-weight: normal;
        }
        .badge-chairperson { background: #ffd700; color: #000; }
        .badge-secretary { background: #17a2b8; color: #fff; }
        .badge-treasurer { background: #28a745; color: #fff; }
        .badge-member { background: #6c757d; color: #fff; }
        .badge-academic { background: #007bff; color: #fff; }
        .badge-cultural { background: #6f42c1; color: #fff; }
        .badge-sports { background: #dc3545; color: #fff; }
        .members-table {
          width: 100%;
          border-collapse: collapse;
        }
        .members-table th,
        .members-table td {
          padding: 10px;
          text-align: left;
          border-bottom: 1px solid #ddd;
        }
        .members-table th {
          background-color: #f2f2f2;
          font-weight: bold;
        }
        .btn-sm {
          padding: 4px 8px;
          font-size: 12px;
        }
        .btn-danger {
          background-color: #dc3545;
          color: white;
          border: none;
          border-radius: 4px;
          cursor: pointer;
        }
        .btn-danger:hover {
          background-color: #c82333;
        }
        .loading {
          text-align: center;
          padding: 20px;
          color: #666;
        }
      `}</style>
    </div>
  );
}

export default Clubs;