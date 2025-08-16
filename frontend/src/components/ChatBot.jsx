// src/components/ChatBot.jsx
import React, { useState, useRef } from 'react';
import ChatInput from './ChatInput';
import '../styles/ChatBot.css'; // optional, keep or adapt to your existing CSS

const PY_NLP_URL = 'http://localhost:8000/chat_api/chat';   
    // Python NLP backend
const ADMIN_REPORT_URL = 'http://localhost:5000/api/admin/report'; // optional Node API for admin reporting

const ChatBot = ({ language = 'hi' }) => {
  const [messages, setMessages] = useState([
    { sender: 'bot', text: language === 'hi' ? 'नमस्ते! मैं आपकी कैसे मदद कर सकता हूँ?' : 'Hello! How can I help you?' }
  ]);
  const [loading, setLoading] = useState(false);
  const boxRef = useRef(null);

  const addMessage = (sender, text) => {
    setMessages(prev => [...prev, { sender, text }]);
    // scroll to bottom
    setTimeout(() => {
      if (boxRef.current) boxRef.current.scrollTop = boxRef.current.scrollHeight;
    }, 50);
  };

  // format multi-line answer into JSX (preserves bullets/newlines)
  const renderMessageText = (text) => {
    if (!text) return null;
    // If the backend returns HTML-like bullets with '-' we keep them.
    return text.split('\n').map((line, i) => <div key={i} style={{ whiteSpace: 'pre-wrap' }}>{line}</div>);
  };

  const reportToAdmin = async (question) => {
    // Try sending to Node admin endpoint if available, otherwise fallback to console/log.
    try {
      const res = await fetch(ADMIN_REPORT_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question })
      });
      if (!res.ok) throw new Error('Admin report failed');
      return true;
    } catch (err) {
      console.warn('Could not send admin report (no backend?), logging locally:', err);
      // fallback: append unanswered to a visible bot message or console
      console.log('Unanswered saved (frontend fallback):', question);
      return false;
    }
  };

  const handleSend = async (userText) => {
    if (!userText || !userText.trim()) return;
    addMessage('user', userText);
    setLoading(true);

    try {
      const resp = await fetch(PY_NLP_URL, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    query_text: userText,
    user_id: "anonymous_user",  // replace with actual user id if available
    language: language          // your component's language prop
  }),
});
      if (!resp.ok) {
        throw new Error(`NLP backend error: ${resp.status}`);
      }

      const data = await resp.json();
      const answer = data.bot_response ?? '';

      if (answer === 'ASK_ADMIN') {
        // Inform user and send to admin
        addMessage('bot', language === 'hi' ? 'माफ़ कीजिए — मैं इसका उत्तर नहीं दे पा रहा/रही। हमने आपका सवाल एडमिन को भेज दिया है।' : "Sorry — I don't have that answer. We've forwarded your query to the admin.");
        await reportToAdmin(userText);
      } else {
        // Show the answer (multi-line friendly)
        addMessage('bot', answer);
      }
    } catch (err) {
      console.error('Error fetching answer:', err);
      addMessage('bot', language === 'hi' ? 'उत्तर लाने में त्रुटि हुई। कृपया बाद में कोशिश करें।' : 'Error fetching answer. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="chat-container">
      <h2>{language === 'hi' ? 'MP Labour Chatbot' : 'MP Labour Chatbot'}</h2>

      <div className="chat-box" ref={boxRef} style={{ maxHeight: '60vh', overflowY: 'auto', padding: '12px', background: '#f8f8f8', borderRadius: 8 }}>
        {messages.map((msg, i) => (
          <div key={i} className={`message ${msg.sender}`} style={{
            display: 'block',
            margin: '8px 0',
            textAlign: msg.sender === 'user' ? 'right' : 'left'
          }}>
            <div style={{
              display: 'inline-block',
              padding: '8px 12px',
              borderRadius: 12,
              background: msg.sender === 'user' ? '#d1e7ff' : '#ffffff',
              boxShadow: msg.sender === 'bot' ? '0 1px 1px rgba(0,0,0,0.05)' : 'none',
              maxWidth: '85%'
            }}>
              {renderMessageText(msg.text)}
            </div>
          </div>
        ))}
        {loading && (
          <div className="message bot" style={{ marginTop: 8 }}>
            <div style={{ display: 'inline-block', padding: '8px 12px', borderRadius: 12, background: '#fff' }}>
              {language === 'hi' ? 'टाइप कर रहे हैं...' : 'Typing...'}
            </div>
          </div>
        )}
      </div>

      <ChatInput onSend={handleSend} language={language} />
    </div>
  );
};

export default ChatBot;
