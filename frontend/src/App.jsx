// src/App.jsx
import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

import Navbar from './components/Navbar';
import Header from './components/Header';
import Footer from './components/Footer';

import Home from './pages/Home';
import ChatBot from './components/ChatBot';
import SignIn from './pages/Login';
import OtpVerify from './pages/OtpVerify';
import Register from './pages/Register';
import AdminLogin from './pages/AdminLogin';
import AdminDashboard from './pages/AdminDashboard';

function App() {
  const [language, setLanguage] = useState('hi'); // default Hindi

  const handleLanguageToggle = () => {
    setLanguage(prev => (prev === 'en' ? 'hi' : 'en'));
  };

  return (
    <Router>
      <Header />
      <Navbar onLanguageToggle={handleLanguageToggle} currentLanguage={language} />
      <main style={{ minHeight: '70vh' }}>
        <Routes>
          <Route path="/" element={<Home language={language} />} />
          <Route path="/signin" element={<SignIn language={language} />} />
          <Route path="/verify-otp" element={<OtpVerify language={language} />} />
          <Route path="/register" element={<Register language={language} />} />
          <Route path="/chatbot" element={<ChatBot language={language} />} />

          {/* Admin */}
          <Route path="/admin" element={<AdminLogin />} />
          <Route path="/admin/dashboard" element={<AdminDashboard />} />
        </Routes>
      </main>
      <Footer />
    </Router>
  );
}

export default App;
