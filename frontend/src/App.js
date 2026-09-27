import React, { useState } from 'react';
import axios from 'axios';

function App() {
  const [payload, setPayload] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    setLoading(true);
    try {
      const res = await axios.post('http://localhost:8000/api/scan/', { payload });
      setResults(res.data);
    } catch (error) {
      console.error("Scanning failed", error);
    }
    setLoading(false);
  };

  return (
    <div className="container mt-5">
      <h2 className="mb-4 text-primary">DevSecOps Scanner Dashboard</h2>
      <div className="card shadow-sm mb-4">
        <div className="card-body">
          <label className="form-label fw-bold">Enter Code or Text to Scan:</label>
          <textarea 
            className="form-control mb-3" 
            rows="5" 
            value={payload} 
            onChange={(e) => setPayload(e.target.value)}
            placeholder='e.g., const AWS_KEY = "AKIA1234567890QWERTY";'
          ></textarea>
          <button className="btn btn-dark" onClick={handleScan} disabled={loading}>
            {loading ? 'Scanning...' : 'Run Security Scan'}
          </button>
        </div>
      </div>

      {results && (
        <div className="alert alert-danger" role="alert">
          <h4 className="alert-heading">Scan Complete</h4>
          <p>Found <strong>{results.findings_count}</strong> vulnerabilities.</p>
          <hr />
          <ul className="mb-0">
            {results.findings.map((f, idx) => (
              <li key={idx}>
                <span className="badge bg-danger me-2">{f.severity}</span>
                {f.vulnerability}: <code>{f.match}</code>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default App;