import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import './Navbar.css';

const Navbar = ({ onLanguageToggle, currentLanguage }) => {
  const location = useLocation();

  const isAdminLoggedIn = !!localStorage.getItem('adminToken');  // <-- changed here
  const isUserLoggedIn = localStorage.getItem('isUserLoggedIn') === 'true';

  const handleLogout = () => {
    localStorage.removeItem('adminToken');  // <-- changed here
    localStorage.removeItem('isUserLoggedIn');
    localStorage.removeItem('user');
    window.location.href = '/';
  };

  return (
    <nav
      className="navbar"
      style={{
        backgroundColor: '#1a237e',
        padding: '10px 20px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}
    >
      <div className="navbar-left">
        <Link
          to="/"
          style={{
            color: '#fff',
            fontWeight: 'bold',
            fontSize: '18px',
            textDecoration: 'none'
          }}
        >
          Kaamgar Sahayak
        </Link>
      </div>

      <div className="navbar-center">
        <Link
          to="/"
          style={{ color: '#fff', margin: '0 10px', textDecoration: 'none' }}
        >
          {currentLanguage === 'hi' ? 'होम' : 'Home'}
        </Link>
        <Link
          to="/chatbot"
          style={{ color: '#fff', margin: '0 10px', textDecoration: 'none' }}
        >
          {currentLanguage === 'hi' ? 'चैटबॉट' : 'Chatbot'}
        </Link>

        {!isUserLoggedIn && !isAdminLoggedIn && (
          <>
            <Link
              to="/signin"
              style={{ color: '#fff', margin: '0 10px', textDecoration: 'none' }}
            >
              {currentLanguage === 'hi' ? 'लॉगिन' : 'Login'}
            </Link>
            <Link
              to="/register"
              style={{ color: '#fff', margin: '0 10px', textDecoration: 'none' }}
            >
              {currentLanguage === 'hi' ? 'रजिस्टर' : 'Register'}
            </Link>
          </>
        )}
      </div>

      <div
        className="navbar-right"
        style={{ display: 'flex', alignItems: 'center', gap: '15px' }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            background: '#fff',
            borderRadius: '20px',
            padding: '2px 5px'
          }}
        >
          <span
            style={{
              color: currentLanguage === 'hi' ? '#1a237e' : '#999',
              fontWeight: 'bold',
              padding: '0 8px'
            }}
          >
            हिंदी
          </span>
          <button
            onClick={onLanguageToggle}
            style={{
              backgroundColor: '#1a237e',
              color: '#fff',
              border: 'none',
              borderRadius: '20px',
              padding: '5px 10px',
              cursor: 'pointer'
            }}
          >
            ⇄
          </button>
          <span
            style={{
              color: currentLanguage === 'en' ? '#1a237e' : '#999',
              fontWeight: 'bold',
              padding: '0 8px'
            }}
          >
            English
          </span>
        </div>

        {(isUserLoggedIn || isAdminLoggedIn) ? (
          <>
            {isAdminLoggedIn && location.pathname !== '/admin/dashboard' && (
              <Link
                to="/admin/dashboard"
                style={{
                  color: '#fff',
                  marginRight: '10px',
                  textDecoration: 'none'
                }}
              >
                Admin Dashboard
              </Link>
            )}
            <button
              onClick={handleLogout}
              style={{
                backgroundColor: '#f44336',
                color: '#fff',
                border: 'none',
                padding: '5px 10px',
                borderRadius: '5px',
                cursor: 'pointer'
              }}
            >
              {currentLanguage === 'hi' ? 'लॉगआउट' : 'Logout'}
            </button>
          </>
        ) : (
          <Link to="/admin" style={{ color: '#fff', textDecoration: 'none' }}>
            {currentLanguage === 'hi' ? 'एडमिन लॉगिन' : 'Admin Login'}
          </Link>
        )}
      </div>
    </nav>
  );
};

export default Navbar;
