import React, { useState } from 'react';
import axios from 'axios';

function App() {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('url');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleScan = async () => {
    setLoading(true);
    setError('');
    setResults(null);
    try {
      const res = await axios.post('http://localhost:8000/api/scan/', { 
        payload: target,
        type: scanType
      });
      setResults(res.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Scan failed to execute');
    }
    setLoading(false);
  };

  return (
    <div className="container mt-5">
      <h2 className="mb-4 text-primary">DevSecOps Scanner Dashboard</h2>
      
      <div className="card shadow-sm mb-4">
        <div className="card-body">
          <div className="mb-3">
            <label className="fw-bold me-3">Scan Mode:</label>
            <div className="form-check form-check-inline">
              <input 
                className="form-check-input" 
                type="radio" 
                id="urlMode" 
                value="url" 
                checked={scanType === 'url'} 
                onChange={() => setScanType('url')} 
              />
              <label className="form-check-label" htmlFor="urlMode">Live Target URL</label>
            </div>
            <div className="form-check form-check-inline">
              <input 
                className="form-check-input" 
                type="radio" 
                id="textMode" 
                value="text" 
                checked={scanType === 'text'} 
                onChange={() => setScanType('text')} 
              />
              <label className="form-check-label" htmlFor="textMode">Source Code / Secrets</label>
            </div>
          </div>

          <label className="form-label fw-bold">
            {scanType === 'url' ? 'Enter Target URL (e.g. http://example.com):' : 'Paste Code Snippet:'}
          </label>
          <textarea 
            className="form-control mb-3" 
            rows={scanType === 'url' ? 2 : 5} 
            value={target} 
            onChange={(e) => setTarget(e.target.value)}
            placeholder={scanType === 'url' ? 'http://testphp.vulnweb.com' : 'const API_KEY = "AKIA1234567890QWERTY";'}
          ></textarea>
          <button className="btn btn-dark" onClick={handleScan} disabled={loading || !target.trim()}>
            {loading ? 'Running Scan...' : 'Launch Security Scan'}
          </button>
        </div>
      </div>

      {error && <div className="alert alert-warning">{error}</div>}

      {results && (
        <div className={`alert ${results.findings_count > 0 ? 'alert-danger' : 'alert-success'}`} role="alert">
          <h4 className="alert-heading">{results.status}</h4>
          <p>Scanned target: <code>{results.target}</code></p>
          <p>Identified Risks: <strong>{results.findings_count}</strong></p>
          {results.findings_count > 0 && (
            <>
              <hr />
              <ul className="mb-0">
                {results.findings.map((f, idx) => (
                  <li key={idx} className="mb-1">
                    <span className={`badge me-2 ${f.severity === 'HIGH' ? 'bg-danger' : 'bg-warning text-dark'}`}>
                      {f.severity}
                    </span>
                    <strong>{f.vulnerability}</strong>: <code>{f.match}</code>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default App;