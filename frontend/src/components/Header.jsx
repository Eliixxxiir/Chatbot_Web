import React from 'react';
import './Header.css';

const Header = () => {
  return (
    <header className="govt-header">
      <img src="/bg.jpeg" alt="Labour Background" className="header-bg-img" />
      <div className="logo-text">
        <img src="/logo.png" alt="Gov Logo" className="govt-logo" />
        <div>
          <div>श्रम एवं रोजगार मंत्रालय</div>
          <div>MINISTRY OF LABOUR & EMPLOYMENT</div>
        </div>
      </div>
    </header>
  );
};

export default Header;
