import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import '../styles/Auth.css';

const BACKEND_URL = "http://127.0.0.1:8000";  // Correct backend URL & port

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();

  const handleLogin = async () => {
    if (!email || !password) {
      alert('कृपया सभी फ़ील्ड भरें');
      return;
    }

    try {
     const res = await fetch(`${BACKEND_URL}/login_api/login`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email, password })
});


      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.detail || "लॉगिन विफल");
      }

      const data = await res.json();
      console.log("Login Response:", data);

      alert("लॉगिन सफल");
      localStorage.setItem("isUserLoggedIn", "true");
      localStorage.setItem("user", JSON.stringify({ email }));

      navigate('/'); // go to home page or dashboard after login
    } catch (err) {
      console.error(err);
      alert(`त्रुटि: ${err.message}`);
    }
  };

  return (
    <div className="auth-container">
      <h2>साइन इन करें</h2>
      <input
        type="email"
        placeholder="ईमेल"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
      />
      <input
        type="password"
        placeholder="पासवर्ड"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <button onClick={handleLogin}>साइन इन</button>
    </div>
  );
};

export default Login;
