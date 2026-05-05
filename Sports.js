import React, { useState, useEffect } from 'react';

function Sports({ token }) {
  const [sports, setSports] = useState([]);
  const [matches, setMatches] = useState([]);
  const [students, setStudents] = useState([]);
  const [achievements, setAchievements] = useState([]);
  const [leaderboard, setLeaderboard] = useState([]);
  const [showMatchForm, setShowMatchForm] = useState(false);
  const [showAchievementForm, setShowAchievementForm] = useState(false);
  const [selectedSport, setSelectedSport] = useState(null);
  const [error, setError] = useState('');
  const [matchData, setMatchData] = useState({
    sport_id: '',
    opponent: '',
    match_date: '',
    venue: '',
    our_score: '',
    opponent_score: '',
    result: '',
    match_type: 'friendly',
    season: '',
    notes: ''
  });
  const [achievementData, setAchievementData] = useState({
    student_id: '',
    sport_id: '',
    achievement_type: '',
    title: '',
    description: '',
    date_awarded: '',
    level: 'school'
  });

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [sportsRes, matchesRes, studentsRes] = await Promise.all([
        fetch('http://localhost:5001/api/v1/sports', { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch('http://localhost:5001/api/v1/sports-matches', { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch('http://localhost:5001/api/v1/students', { headers: { 'Authorization': `Bearer ${token}` } })
      ]);
      
      setSports(await sportsRes.json());
      setMatches(await matchesRes.json());
      setStudents(await studentsRes.json());
      
      // Fetch leaderboard
      const leaderboardRes = await fetch('http://localhost:5001/api/v1/sports/leaderboard', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setLeaderboard(await leaderboardRes.json());
    } catch (error) {
      console.error('Error fetching data:', error);
      setError('Failed to load data');
    }
  };

  const handleMatchSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    // Prepare match data with proper date format
    const submitData = {
      ...matchData,
      sport_id: parseInt(matchData.sport_id, 10),
      our_score: matchData.our_score ? parseInt(matchData.our_score, 10) : null,
      opponent_score: matchData.opponent_score ? parseInt(matchData.opponent_score, 10) : null,
      match_date: matchData.match_date ? matchData.match_date + ':00' : null // Add seconds
    };
    
    console.log('Submitting match data:', submitData);
    
    try {
      const response = await fetch('http://localhost:5001/api/v1/sports-matches', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(submitData)
      });
      
      const data = await response.json();
      
      if (response.ok) {
        alert('Match recorded successfully!');
        setShowMatchForm(false);
        fetchData();
        setMatchData({
          sport_id: '',
          opponent: '',
          match_date: '',
          venue: '',
          our_score: '',
          opponent_score: '',
          result: '',
          match_type: 'friendly',
          season: '',
          notes: ''
        });
      } else {
        setError(data.error || 'Failed to record match');
        console.error('Server error:', data);
      }
    } catch (error) {
      console.error('Error:', error);
      setError('Error recording match. Please check your connection.');
    }
  };

  const handleAchievementSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    // Prepare achievement data with proper types
    const submitData = {
      ...achievementData,
      student_id: parseInt(achievementData.student_id, 10),
      sport_id: parseInt(achievementData.sport_id, 10),
      date_awarded: achievementData.date_awarded
    };
    
    console.log('Submitting achievement data:', submitData);
    
    try {
      const response = await fetch('http://localhost:5001/api/v1/sports-achievements', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(submitData)
      });
      
      const data = await response.json();
      
      if (response.ok) {
        alert('Achievement recorded successfully!');
        setShowAchievementForm(false);
        fetchData();
        setAchievementData({
          student_id: '',
          sport_id: '',
          achievement_type: '',
          title: '',
          description: '',
          date_awarded: '',
          level: 'school'
        });
      } else {
        setError(data.error || 'Failed to record achievement');
        console.error('Server error:', data);
      }
    } catch (error) {
      console.error('Error:', error);
      setError('Error recording achievement. Please check your connection.');
    }
  };

  const getResultBadge = (result) => {
    switch(result) {
      case 'win': return <span className="badge badge-success">🏆 Win</span>;
      case 'loss': return <span className="badge badge-danger">❌ Loss</span>;
      case 'draw': return <span className="badge badge-warning">🤝 Draw</span>;
      default: return <span className="badge">{result}</span>;
    }
  };

  const achievementTypes = ['tournament_winner', 'top_scorer', 'most_valuable', 'best_defender', 'sportsmanship', 'record_breaker'];
  const levels = ['school', 'district', 'provincial', 'national'];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h2>⚽ Sports Management</h2>
        <div>
          <button className="btn btn-primary" onClick={() => {
            setShowMatchForm(!showMatchForm);
            setShowAchievementForm(false);
            setError('');
          }} style={{ marginRight: '1rem' }}>
            {showMatchForm ? 'Cancel' : '+ Record Match'}
          </button>
          <button className="btn btn-primary" onClick={() => {
            setShowAchievementForm(!showAchievementForm);
            setShowMatchForm(false);
            setError('');
          }}>
            {showAchievementForm ? 'Cancel' : '+ Add Achievement'}
          </button>
        </div>
      </div>

      {error && (
        <div className="alert alert-error" style={{ backgroundColor: '#f8d7da', color: '#721c24', padding: '10px', borderRadius: '5px', marginBottom: '1rem' }}>
          ❌ {error}
        </div>
      )}

      {showMatchForm && (
        <div className="card">
          <h3>Record Match Result</h3>
          <form onSubmit={handleMatchSubmit}>
            <div className="form-row">
              <div className="form-group">
                <label>Sport *</label>
                <select
                  value={matchData.sport_id}
                  onChange={(e) => setMatchData({...matchData, sport_id: e.target.value})}
                  required
                >
                  <option value="">Select Sport</option>
                  {sports.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
                </select>
              </div>
              
              <div className="form-group">
                <label>Opponent *</label>
                <input
                  type="text"
                  value={matchData.opponent}
                  onChange={(e) => setMatchData({...matchData, opponent: e.target.value})}
                  required
                />
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Match Date & Time *</label>
                <input
                  type="datetime-local"
                  value={matchData.match_date}
                  onChange={(e) => setMatchData({...matchData, match_date: e.target.value})}
                  required
                />
                <small>Select date and time of the match</small>
              </div>
              
              <div className="form-group">
                <label>Venue</label>
                <input
                  type="text"
                  value={matchData.venue}
                  onChange={(e) => setMatchData({...matchData, venue: e.target.value})}
                  placeholder="Home/Away/School field"
                />
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Our Score</label>
                <input
                  type="number"
                  min="0"
                  value={matchData.our_score}
                  onChange={(e) => setMatchData({...matchData, our_score: e.target.value})}
                />
              </div>
              
              <div className="form-group">
                <label>Opponent Score</label>
                <input
                  type="number"
                  min="0"
                  value={matchData.opponent_score}
                  onChange={(e) => setMatchData({...matchData, opponent_score: e.target.value})}
                />
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Result</label>
                <select
                  value={matchData.result}
                  onChange={(e) => {
                    setMatchData({...matchData, result: e.target.value});
                    // Auto-calculate result based on scores if both are entered
                    if (matchData.our_score !== '' && matchData.opponent_score !== '') {
                      const ourScore = parseInt(matchData.our_score);
                      const oppScore = parseInt(matchData.opponent_score);
                      if (ourScore > oppScore) setMatchData({...matchData, result: 'win'});
                      else if (ourScore < oppScore) setMatchData({...matchData, result: 'loss'});
                      else if (ourScore === oppScore) setMatchData({...matchData, result: 'draw'});
                    }
                  }}
                >
                  <option value="">Select Result</option>
                  <option value="win">Win</option>
                  <option value="loss">Loss</option>
                  <option value="draw">Draw</option>
                </select>
              </div>
              
              <div className="form-group">
                <label>Match Type</label>
                <select
                  value={matchData.match_type}
                  onChange={(e) => setMatchData({...matchData, match_type: e.target.value})}
                >
                  <option value="friendly">Friendly</option>
                  <option value="league">League</option>
                  <option value="tournament">Tournament</option>
                  <option value="knockout">Knockout</option>
                </select>
              </div>
            </div>

            <div className="form-group">
              <label>Notes</label>
              <textarea
                value={matchData.notes}
                onChange={(e) => setMatchData({...matchData, notes: e.target.value})}
                rows="2"
                placeholder="Additional notes about the match"
              />
            </div>

            <button type="submit" className="btn btn-primary">Record Match</button>
          </form>
        </div>
      )}

      {showAchievementForm && (
        <div className="card">
          <h3>Add Achievement</h3>
          <form onSubmit={handleAchievementSubmit}>
            <div className="form-row">
              <div className="form-group">
                <label>Student *</label>
                <select
                  value={achievementData.student_id}
                  onChange={(e) => setAchievementData({...achievementData, student_id: e.target.value})}
                  required
                >
                  <option value="">Select Student</option>
                  {students.map(s => <option key={s.id} value={s.id}>{s.full_name}</option>)}
                </select>
              </div>
              
              <div className="form-group">
                <label>Sport *</label>
                <select
                  value={achievementData.sport_id}
                  onChange={(e) => setAchievementData({...achievementData, sport_id: e.target.value})}
                  required
                >
                  <option value="">Select Sport</option>
                  {sports.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Achievement Title *</label>
                <input
                  type="text"
                  value={achievementData.title}
                  onChange={(e) => setAchievementData({...achievementData, title: e.target.value})}
                  required
                />
              </div>
              
              <div className="form-group">
                <label>Achievement Type</label>
                <select
                  value={achievementData.achievement_type}
                  onChange={(e) => setAchievementData({...achievementData, achievement_type: e.target.value})}
                >
                  <option value="">Select Type</option>
                  {achievementTypes.map(t => <option key={t} value={t}>{t.replace('_', ' ').toUpperCase()}</option>)}
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Date Awarded *</label>
                <input
                  type="date"
                  value={achievementData.date_awarded}
                  onChange={(e) => setAchievementData({...achievementData, date_awarded: e.target.value})}
                  required
                />
              </div>
              
              <div className="form-group">
                <label>Level</label>
                <select
                  value={achievementData.level}
                  onChange={(e) => setAchievementData({...achievementData, level: e.target.value})}
                >
                  {levels.map(l => <option key={l} value={l}>{l.toUpperCase()}</option>)}
                </select>
              </div>
            </div>

            <div className="form-group">
              <label>Description</label>
              <textarea
                value={achievementData.description}
                onChange={(e) => setAchievementData({...achievementData, description: e.target.value})}
                rows="3"
                placeholder="Describe the achievement"
              />
            </div>

            <button type="submit" className="btn btn-primary">Add Achievement</button>
          </form>
        </div>
      )}

      <div className="stats-grid">
        <div className="card">
          <h3>🏆 Sports Leaderboard</h3>
          {leaderboard.length === 0 ? (
            <p>No achievements recorded yet.</p>
          ) : (
            <table className="leaderboard-table">
              <thead>
                <tr>
                  <th>Rank</th>
                  <th>Student</th>
                  <th>Achievements</th>
                </tr>
              </thead>
              <tbody>
                {leaderboard.map((student, idx) => (
                  <tr key={student.student_id}>
                    <td><strong>#{idx + 1}</strong></td>
                    <td>{student.student_name}</td>
                    <td><span className="badge badge-primary">{student.achievements_count}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="card">
          <h3>Recent Matches</h3>
          {matches.length === 0 ? (
            <p>No matches recorded yet.</p>
          ) : (
            <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
              {matches.map(match => (
                <div key={match.id} style={{ marginBottom: '1rem', padding: '0.75rem', borderBottom: '1px solid #eee', borderRadius: '4px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <strong>{match.sport}</strong>
                    {getResultBadge(match.result)}
                  </div>
                  <div style={{ marginTop: '5px' }}>
                    <strong>vs {match.opponent}</strong>
                  </div>
                  <div>
                    Score: <strong>{match.our_score || '?'}</strong> - <strong>{match.opponent_score || '?'}</strong>
                  </div>
                  <div style={{ fontSize: '12px', color: '#666', marginTop: '5px' }}>
                    📅 {new Date(match.match_date).toLocaleDateString()} 
                    {match.venue && ` 📍 ${match.venue}`}
                    {match.match_type && ` 🏷️ ${match.match_type.toUpperCase()}`}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <style jsx>{`
        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
          gap: 1rem;
          margin-top: 1rem;
        }
        .card {
          background: white;
          border-radius: 8px;
          padding: 1rem;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .badge {
          padding: 3px 8px;
          border-radius: 3px;
          font-size: 11px;
          font-weight: normal;
        }
        .badge-success {
          background-color: #28a745;
          color: white;
        }
        .badge-danger {
          background-color: #dc3545;
          color: white;
        }
        .badge-warning {
          background-color: #ffc107;
          color: black;
        }
        .badge-primary {
          background-color: #007bff;
          color: white;
        }
        .leaderboard-table {
          width: 100%;
          border-collapse: collapse;
        }
        .leaderboard-table th,
        .leaderboard-table td {
          padding: 10px;
          text-align: left;
          border-bottom: 1px solid #ddd;
        }
        .form-row {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 1rem;
          margin-bottom: 1rem;
        }
        .form-group {
          margin-bottom: 1rem;
        }
        .form-group label {
          display: block;
          margin-bottom: 0.5rem;
          font-weight: bold;
        }
        .form-group input,
        .form-group select,
        .form-group textarea {
          width: 100%;
          padding: 8px;
          border: 1px solid #ddd;
          border-radius: 4px;
        }
        .btn {
          padding: 10px 20px;
          border: none;
          border-radius: 4px;
          cursor: pointer;
          font-size: 14px;
        }
        .btn-primary {
          background-color: #007bff;
          color: white;
        }
        .btn-primary:hover {
          background-color: #0056b3;
        }
      `}</style>
    </div>
  );
}

export default Sports;