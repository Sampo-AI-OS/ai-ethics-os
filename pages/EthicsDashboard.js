import React, { useState, useEffect } from 'react';
import axios from 'axios';
import ScoreVisualization from '../components/ScoreChart';

function EthicsDashboard() {
  const [modelScores, setModelScores] = useState([]);
  
  useEffect(() => {
    async function fetchScores() {
      try {
        const response = await axios.get('/api/scores', {
          headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
        });
        setModelScores(response.data);
      } catch (error) {
        console.error('Failed to load scores:', error.response?.data || 'Unknown');
      }
    }
    
    fetchScores();
  }, []);

  return (
    <div className="dashboard">
      <h1>AI Ethics Compliance Dashboard</h1>
      
      {modelScores.map((score, index) => (
        <div key={index} className="score-card">
          <ScoreVisualization 
            score={score.current_score}
            violations={score.violation_rules.length}
          />
          
          <div className="violation-details">
            <strong>Model ID:</strong> {score.model_id}<br/>
            <strong>Status:</strong>
            {score.current_score >= 80 ? 'Compliant' : 
             score.current_score >= 60 ? 'Needs Review' : 'Critical Risk'}
          </div>
        </div>
      ))}
    </div>
  );
}

export default EthicsDashboard;