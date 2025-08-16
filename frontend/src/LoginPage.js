import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const LoginPage = () => {
  const [isAdmin, setIsAdmin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleToggle = () => {
    setIsAdmin((prev) => !prev);
    setError('');
    setUsername('');
    setPassword('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!username || !password) {
      setError('Please enter both username and password.');
      return;
    }
    if (isAdmin) {
      // Admin login
      try {
        const backendApiUrl = process.env.REACT_APP_BACKEND_API_URL || 'http://127.0.0.1:8000';
        const res = await fetch(`${backendApiUrl}/admin_api/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
        });
        const data = await res.json();
        if (res.ok && data.access_token) {
          localStorage.setItem('adminToken', data.access_token);
          navigate('/admin');
        } else {
          setError(data.detail || 'Login failed.');
        }
      } catch (err) {
        setError('Network error.');
      }
    } else {
      // User login (for demo, just store username)
      localStorage.setItem('chatbotUserId', username);
      navigate('/');
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-100">
      <div className="bg-white p-8 rounded shadow-md w-full max-w-md">
        <h2 className="text-2xl font-bold mb-4 text-center">{isAdmin ? 'Admin Login' : 'User Login'}</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="text"
            placeholder={isAdmin ? 'Admin Username' : 'User ID'}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full p-2 border rounded"
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className={`w-full p-2 border rounded ${isAdmin ? '' : 'hidden'}`}
            style={{ display: isAdmin ? 'block' : 'none' }}
          />
          {error && <p className="text-red-500 text-sm">{error}</p>}
          <button type="submit" className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700">
            {isAdmin ? 'Login as Admin' : 'Login as User'}
          </button>
        </form>
        <button
          onClick={handleToggle}
          className="mt-4 w-full bg-gray-200 text-gray-700 py-2 rounded hover:bg-gray-300"
        >
          {isAdmin ? 'Switch to User Login' : 'Switch to Admin Login'}
        </button>
      </div>
    </div>
  );
};

export default LoginPage;
