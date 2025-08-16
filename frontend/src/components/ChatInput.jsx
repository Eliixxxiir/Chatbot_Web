// src/components/ChatInput.jsx
import React, { useState, useEffect } from 'react';
import SpeechRecognition, { useSpeechRecognition } from 'react-speech-recognition';
import './ChatInput.css'; // optional - your CSS

const ChatInput = ({ onSend, language = 'hi' }) => {
  const [inputText, setInputText] = useState('');
  const { transcript, listening, resetTranscript } = useSpeechRecognition();

  // When voice stops, send the transcript automatically (if any)
  useEffect(() => {
    if (!listening && transcript) {
      onSend(transcript);
      resetTranscript();
    }
    // only want to run when listening changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [listening]);

  const handleSendClick = () => {
    const trimmed = inputText.trim();
    if (trimmed !== '') {
      onSend(trimmed);
      setInputText('');
    }
  };

  const handleMicClick = () => {
    if (!SpeechRecognition.browserSupportsSpeechRecognition()) {
      alert(language === 'hi' ? 'आपका ब्राउज़र आवाज़ पहचान का समर्थन नहीं करता।' : 'Your browser does not support speech recognition.');
      return;
    }

    if (!listening) {
      // language code
      const langCode = language === 'hi' ? 'hi-IN' : 'en-US';
      SpeechRecognition.startListening({ continuous: false, language: langCode });
    } else {
      SpeechRecognition.stopListening();
    }
  };

  return (
    <div className="input-container" style={{ display: 'flex', gap: 8, marginTop: 12 }}>
      <input
        type="text"
        placeholder={language === 'hi' ? 'अपना प्रश्न टाइप करें...' : 'Type your question...'}
        value={inputText}
        onChange={(e) => setInputText(e.target.value)}
        onKeyDown={(e) => { if (e.key === 'Enter') handleSendClick(); }}
        className="chat-input"
        style={{ flex: 1, padding: '10px 12px', borderRadius: 6, border: '1px solid #ccc' }}
      />
      <button onClick={handleSendClick} className="send-btn" style={{ padding: '10px 12px', borderRadius: 6, border: 'none', background: '#1976d2', color: '#fff' }}>
        {language === 'hi' ? 'भेजें' : 'Send'}
      </button>
      <button onClick={handleMicClick} className="mic-btn" style={{ padding: '10px 12px', borderRadius: 6, border: '1px solid #1976d2', background: listening ? '#e3f2fd' : '#fff', cursor: 'pointer' }}>
        {listening ? '🎙️...' : '🎤'}
      </button>
    </div>
  );
};

export default ChatInput;
