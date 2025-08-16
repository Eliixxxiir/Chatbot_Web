import React, { useEffect, useState } from 'react';

const AdminDashboard = () => {
  const [unansweredLogs, setUnansweredLogs] = useState([]);
  const [allLogs, setAllLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Replace with your actual admin token retrieval logic
  const adminToken = localStorage.getItem('adminToken');

  // If no token, show error and do not fetch
  const isAuthenticated = !!adminToken;

  useEffect(() => {
    if (!isAuthenticated) {
      setError('Admin token not found. Please log in as admin.');
      setLoading(false);
      return;
    }
    const fetchLogs = async () => {
      setLoading(true);
      setError(null);
      try {
        const backendApiUrl = process.env.REACT_APP_BACKEND_API_URL || 'http://127.0.0.1:8000';
        const unansweredRes = await fetch(`${backendApiUrl}/admin_api/unanswered_logs`, {
          headers: { Authorization: `Bearer ${adminToken}` }
        });
        const allRes = await fetch(`${backendApiUrl}/admin_api/all_logs`, {
          headers: { Authorization: `Bearer ${adminToken}` }
        });
        if (unansweredRes.status === 401 || allRes.status === 401) {
          throw new Error('Unauthorized. Please log in as admin.');
        }
        if (!unansweredRes.ok || !allRes.ok) throw new Error('Failed to fetch logs');
        setUnansweredLogs(await unansweredRes.json());
        setAllLogs(await allRes.json());
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    fetchLogs();
  }, [adminToken, isAuthenticated]);

  return (
    <div className="max-w-4xl mx-auto p-6">
      <h2 className="text-2xl font-bold mb-4">Admin Dashboard</h2>
  {loading ? <p>Loading logs...</p> : error ? <p className="text-red-500">{error}</p> : (
        <>
          <section className="mb-8">
            <h3 className="text-xl font-semibold mb-2">Unanswered Queries</h3>
            <div className="bg-white shadow rounded p-4">
              {unansweredLogs.length === 0 ? <p>No unanswered queries.</p> : (
                <ul className="divide-y">
                  {unansweredLogs.map(log => (
                    <li key={log._id} className="py-2">
                      <strong>User:</strong> {log.user_id} <br />
                      <strong>Query:</strong> {log.query_text} <br />
                      <strong>Time:</strong> {log.timestamp}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>
          <section>
            <h3 className="text-xl font-semibold mb-2">All Query Logs</h3>
            <div className="bg-white shadow rounded p-4 max-h-96 overflow-y-auto">
              {allLogs.length === 0 ? <p>No logs found.</p> : (
                <ul className="divide-y">
                  {allLogs.map(log => (
                    <li key={log._id} className="py-2">
                      <strong>User:</strong> {log.user_id} <br />
                      <strong>Query:</strong> {log.query_text} <br />
                      <strong>Bot Response:</strong> {log.bot_response_text} <br />
                      <strong>Status:</strong> {log.status} <br />
                      <strong>Time:</strong> {log.timestamp}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>
        </>
      )}
    </div>
  );
};

export default AdminDashboard;
