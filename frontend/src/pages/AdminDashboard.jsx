import React, { useEffect, useState } from "react";
import axios from "axios";

const API_BASE = "http://localhost:8000/admin_api"; // Change if needed

const AdminDashboard = () => {
  const [unanswered, setUnanswered] = useState([]);
  const [logs, setLogs] = useState([]);
  const [activeRow, setActiveRow] = useState(null);
  const [chooseAction, setChooseAction] = useState(""); // "mark" or "answer"
  const [markStatus, setMarkStatus] = useState("");
  const [answerText, setAnswerText] = useState("");

  // Always get token from localStorage
  const getToken = () => localStorage.getItem('adminToken') || "";

  // Fetch unanswered queries and logs
  const [markedQueries, setMarkedQueries] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const token = getToken();
        const unansweredRes = await axios.get(`${API_BASE}/unanswered_queries`, {
          headers: { Authorization: `Bearer ${token}` },
        });
  // Only show queries with status 'unanswered'
  const filtered = unansweredRes.data.filter(q => (q.status === 'unanswered' || !q.status));
  setUnanswered(filtered);

        const logsRes = await axios.get(`${API_BASE}/logs`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        setLogs(logsRes.data);

        // Fetch marked queries from admin_marking
        const markedRes = await axios.get(`${API_BASE}/marked_queries`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        setMarkedQueries(markedRes.data.map(m => m.query_id));
      } catch (err) {
        console.error("Error fetching data", err);
      }
    };
    fetchData();
  }, []);

  // Handle Choose button
  const handleChoose = (rowId) => {
    setActiveRow(rowId);
    setChooseAction("");
    setMarkStatus("");
    setAnswerText("");
  };

  // Handle Mark

  const handleMark = async (status, query) => {
    try {
      const token = getToken();
      await axios.post(
        `${API_BASE}/mark_query/${query._id}`,
        {
          status,
          query_log: query,
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      alert("Marked successfully!");
      setActiveRow(null);
      setChooseAction("");
      // Optionally refresh unanswered
    } catch (err) {
      alert("Error marking query");
    }
  };

  // Handle Answer

  const handleAnswerSubmit = async (query) => {
    try {
      const token = getToken();
      await axios.post(
        `${API_BASE}/answer_query/${query._id}`,
        {
          answer: answerText,
          query_log: query,
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      alert("Answer submitted!");
      setActiveRow(null);
      setChooseAction("");
      setAnswerText("");
      // Optionally refresh unanswered
    } catch (err) {
      alert("Error submitting answer");
    }
  };

  // Sorting and pagination state
  const [unansweredSort, setUnansweredSort] = useState('newest');
  const [logsSort, setLogsSort] = useState('newest');
  const unansweredSorted = [...unanswered].sort((a, b) => {
    const dateA = new Date(a.date || a.asked_at || a.timestamp || a.created_at || 0);
    const dateB = new Date(b.date || b.asked_at || b.timestamp || b.created_at || 0);
    return unansweredSort === 'newest' ? dateB - dateA : dateA - dateB;
  });
  const logsSorted = [...logs].sort((a, b) => {
    const dateA = new Date(a.date || a.asked_at || a.timestamp || a.created_at || 0);
    const dateB = new Date(b.date || b.asked_at || b.timestamp || b.created_at || 0);
    return logsSort === 'newest' ? dateB - dateA : dateA - dateB;
  });
  // Pagination: show only first 15
  const unansweredPage = unansweredSorted.slice(0,);
  const logsPage = logsSorted.slice(0,);

  return (
    <div className="admin-dashboard" style={{ display: 'flex', gap: '2rem', alignItems: 'flex-start' }}>
      <div style={{ flex: 1 }}>
        <h2>Unanswered Queries</h2>
        <div style={{ marginBottom: '0.5rem' }}>
          <button onClick={() => setUnansweredSort('newest')}>Show Newer to Older</button>
          <button onClick={() => setUnansweredSort('oldest')}>Show Older to Newer</button>
        </div>
        <div style={{ maxHeight: '400px', overflowY: 'auto', border: '1px solid #ccc', borderRadius: '6px' }}>
          {unansweredPage.length === 0 ? (
            <p style={{ padding: '1rem' }}>No unanswered queries found.</p>
          ) : (
            <table style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th>Question</th>
                  <th>User</th>
                  <th>Date</th>
                  <th>Choose</th>
                </tr>
              </thead>
              <tbody>
                {unansweredPage.map((query) => (
                  <tr key={query._id}>
                    <td>{query.question || query.query_text || query.text || "N/A"}</td>
                    <td>{query.user || query.user_id || query.asked_by || "N/A"}</td>
                    <td>{query.date || query.asked_at || query.timestamp || query.created_at || "N/A"}</td>
                    <td>
                      {markedQueries.includes(query._id) ? (
                        <button style={{ backgroundColor: 'orange', color: 'white', cursor: 'not-allowed' }} disabled>Marked</button>
                      ) : activeRow === query._id ? (
                        <>
                          {!chooseAction && (
                            <>
                              <button onClick={() => setChooseAction("mark")}>Mark</button>
                              <button onClick={() => setChooseAction("answer")}>Answer</button>
                            </>
                          )}
                          {chooseAction === "mark" && (
                            <div>
                              <button onClick={() => handleMark("Irrelevant", query)}>Irrelevant</button>
                              <button onClick={() => handleMark("Answerable", query)}>Answerable</button>
                              <button onClick={() => handleMark("Pending", query)}>Pending</button>
                            </div>
                          )}
                          {chooseAction === "answer" && (
                            <div>
                              <textarea
                                value={answerText}
                                onChange={(e) => setAnswerText(e.target.value)}
                                placeholder="Type your answer here"
                              />
                              <button onClick={() => handleAnswerSubmit(query)}>Submit</button>
                            </div>
                          )}
                        </>
                      ) : (
                        <button onClick={() => handleChoose(query._id)}>Choose</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
      <div style={{ flex: 1 }}>
        <h2>Chatbot Logs</h2>
        <div style={{ marginBottom: '0.5rem' }}>
          <button onClick={() => setLogsSort('newest')}>Show Newer to Older</button>
          <button onClick={() => setLogsSort('oldest')}>Show Older to Newer</button>
        </div>
        <div style={{ maxHeight: '400px', overflowY: 'auto', border: '1px solid #ccc', borderRadius: '6px' }}>
          {logsPage.length === 0 ? (
            <p style={{ padding: '1rem' }}>No logs found.</p>
          ) : (
            <table style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th>Question</th>
                  <th>Answer</th>
                  <th>User</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {logsPage.map((log) => (
                  <tr key={log._id}>
                    <td>{log.question || log.query_text || log.text || "N/A"}</td>
                    <td>{log.answer || log.response || "N/A"}</td>
                    <td>{log.user || log.user_id || log.asked_by || "N/A"}</td>
                    <td>{log.date || log.asked_at || log.timestamp || log.created_at || "N/A"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
};

export default AdminDashboard;
// src/pages/AdminDashboard.jsx
