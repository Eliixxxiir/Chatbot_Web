import React, { useState, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import '../styles/Auth.css'; // Reuse existing CSS

const OtpVerify = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const phone = location.state?.phone || '';
  const [otp, setOtp] = useState(['', '', '', '', '', '']);
  const [loading, setLoading] = useState(false);

  const inputsRef = useRef([]);

  const handleChange = (e, index) => {
    const value = e.target.value;
    if (/^\d*$/.test(value)) {
      const newOtp = [...otp];
      newOtp[index] = value;
      setOtp(newOtp);

      if (value && index < 5) {
        inputsRef.current[index + 1].focus();
      }
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    const enteredOtp = otp.join('');
    if (enteredOtp.length === 6) {
      setLoading(true);
      setTimeout(() => {
        setLoading(false);
        alert(`OTP Verified for ${phone}`);
        navigate('/');
      }, 2000);  // Simulate backend verification delay
    } else {
      alert('कृपया पूरा OTP दर्ज करें');
    }
  };

  return (
    <div className="auth-container">
      {loading ? (
        <div className="spinner"></div>
      ) : (
        <>
          <h2>OTP सत्यापन</h2>
          <p style={{ marginBottom: '20px' }}>{phone} पर भेजा गया OTP दर्ज करें</p>
          <form onSubmit={handleSubmit}>
            <div className="otp-inputs">
              {otp.map((digit, index) => (
                <input
                  key={index}
                  type="text"
                  maxLength="1"
                  value={digit}
                  ref={(el) => (inputsRef.current[index] = el)}
                  onChange={(e) => handleChange(e, index)}
                />
              ))}
            </div>
            <button type="submit">सत्यापित करें</button>
          </form>
        </>
      )}
    </div>
  );
};

export default OtpVerify;
