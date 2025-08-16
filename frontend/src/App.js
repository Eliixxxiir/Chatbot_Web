import React, { useState, useEffect, useRef } from 'react';
import { v4 as uuidv4 } from 'uuid'; // For generating unique user IDs
import AdminDashboard from './AdminDashboard';
import { BrowserRouter as Router, Route, Routes, Link } from 'react-router-dom';

// Main App Component - This is your primary web framework for the chatbot
const App = () => {
  // State to manage chat messages
  const [messages, setMessages] = useState([]);
  // State for the text input field
  const [inputText, setInputText] = useState('');
  // State to manage microphone listening status
  const [isListening, setIsListening] = useState(false);
  // State for selected language: 'en' for English, 'hi' for Hindi, 'hinglish' for Hinglish
  const [language, setLanguage] = useState('en');
  // Ref for scrolling to the latest message in the chat
  const messagesEndRef = useRef(null);
  // Unique user ID for logging (generated once per session)
  const [userId, setUserId] = useState(() => {
    // Try to get userId from localStorage, otherwise generate a new one
    const storedUserId = localStorage.getItem('chatbotUserId');
    if (storedUserId) {
      return storedUserId;
    }
    const newUserId = uuidv4();
    localStorage.setItem('chatbotUserId', newUserId);
    return newUserId;
  });
  // State for loading indicator
  const [isLoading, setIsLoading] = useState(false);

  // --- Web Speech API Setup ---
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  const recognitionRef = useRef(null);
  const utteranceRef = useRef(null); // For Text-to-Speech

  // Effect hook for setting up Speech Recognition
  useEffect(() => {
    if (SpeechRecognition) {
      recognitionRef.current = new SpeechRecognition();
      recognitionRef.current.continuous = false;
      recognitionRef.current.interimResults = false;
      recognitionRef.current.lang = getSpeechRecognitionLangCode(language);

      recognitionRef.current.onstart = () => {
        setIsListening(true);
        console.log('Voice recognition started. Speak now.');
        setMessages((prevMessages) => [
          ...prevMessages,
          { sender: 'system', text: getSystemMessage('listening', language), timestamp: new Date() }
        ]);
      };

      recognitionRef.current.onresult = (event) => {
        const transcript = event.results[0][0].transcript;
        setInputText(transcript);
        setIsListening(false);
        console.log('Voice recognition result:', transcript);
        handleSendMessage(transcript);
      };

      recognitionRef.current.onerror = (event) => {
        console.error('Speech recognition error:', event.error);
        setIsListening(false);
        setMessages((prevMessages) => [
          ...prevMessages,
          { sender: 'system', text: getSystemMessage('speech_error', language), timestamp: new Date() }
        ]);
      };

      recognitionRef.current.onend = () => {
        setIsListening(false);
        console.log('Voice recognition ended.');
      };
    } else {
      console.warn('Speech Recognition API not supported in this browser.');
      setMessages((prevMessages) => [
        ...prevMessages,
        { sender: 'system', text: getSystemMessage('browser_support_warning', language), timestamp: new Date() }
      ]);
    }

    return () => {
      if (recognitionRef.current) {
        recognitionRef.current.stop();
      }
    };
  }, [language, SpeechRecognition]);

  // Effect hook for scrolling to the bottom of the chat window
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Helper function to get the correct language code for SpeechRecognition/Synthesis
  const getSpeechRecognitionLangCode = (lang) => {
    switch (lang) {
      case 'en': return 'en-IN';
      case 'hi':
      case 'hinglish': return 'hi-IN';
      default: return 'en-IN';
    }
  };

  // Helper function for system messages based on language
  const getSystemMessage = (key, lang) => {
    const messages = {
      'listening': {
        'en': 'Listening...',
        'hi': 'सुन रहा हूँ...',
        'hinglish': 'Sun raha hoon...'
      },
      'speech_error': {
        'en': 'Sorry, I could not understand your voice. Please try typing.',
        'hi': 'क्षमा करें, मैं आपकी आवाज़ समझ नहीं पाया। कृपया टाइप करने का प्रयास करें।',
        'hinglish': 'Sorry, main aapki awaaz samajh nahi paya. Pls type karke try karein.'
      },
      'browser_support_warning': {
        'en': 'Voice input/output is not fully supported in this browser.',
        'hi': 'इस ब्राउज़र में ध्वनि इनपुट/आउटपुट पूरी तरह से समर्थित नहीं है।',
        'hinglish': 'Is browser mein voice input/output fully support nahi hai.'
      },
      'empty_message': {
        'en': 'Please type or speak something.',
        'hi': 'कृपया कुछ टाइप करें या बोलें।',
        'hinglish': 'Pls kuch type karein ya bolein.'
      },
      'api_error': {
        'en': 'An error occurred. Please try again later.',
        'hi': 'एक त्रुटि हुई। कृपया बाद में पुनः प्रयास करें।',
        'hinglish': 'Kuch error ho gaya. Pls baad mein try karein.'
      },
      'initial_greeting': {
        'en': `Hello! I'm Kaamgar Sahayak, your AI assistant for labor information in Madhya Pradesh, India. I can help you understand your rights regarding wage laws, working hours, and more. How can I help you?`,
        'hi': `नमस्ते! मैं कामगार सहायक हूँ, मध्य प्रदेश, भारत में श्रम जानकारी के लिए आपका AI सहायक। मैं आपको मजदूरी कानूनों, काम के घंटों और आपके अधिकारों के बारे में जानकारी समझने में मदद कर सकता हूँ। मैं आपकी कैसे मदद कर सकता हूँ?`,
        'hinglish': `Hello! Main Kaamgar Sahayak hoon, aapka AI assistant Madhya Pradesh, India mein labour information ke liye. Main aapki madad kar sakta hoon wage laws, working hours aur aapke rights samajhne mein. Main aapki kaise help kar sakta hoon?`
      }
    };
    return messages[key]?.[lang] || messages[key]?.['en'];
  };

  // Initial greeting from the bot
  useEffect(() => {
    setMessages((prevMessages) => [
      ...prevMessages,
      { sender: 'bot', text: getSystemMessage('initial_greeting', language), timestamp: new Date() }
    ]);
    speakText(getSystemMessage('initial_greeting', language));
  }, []); // Run only once on component mount

  // Function to speak text (Text-to-Speech)
  const speakText = (text) => {
    if ('speechSynthesis' in window) {
      if (window.speechSynthesis.speaking) {
        window.speechSynthesis.cancel();
      }
      utteranceRef.current = new SpeechSynthesisUtterance(text);
      utteranceRef.current.lang = getSpeechRecognitionLangCode(language);
      window.speechSynthesis.speak(utteranceRef.current);
    } else {
      console.warn('Text-to-Speech not supported in this browser.');
    }
  };

  // Function to handle sending messages (text or from speech)
  const handleSendMessage = async (message = inputText) => {
    const trimmedMessage = message.trim();
    if (!trimmedMessage) {
      setMessages((prevMessages) => [
        ...prevMessages,
        { sender: 'system', text: getSystemMessage('empty_message', language), timestamp: new Date() }
      ]);
      return;
    }

    setMessages((prevMessages) => [
      ...prevMessages,
      { sender: 'user', text: trimmedMessage, timestamp: new Date() }
    ]);
    setInputText('');
    setIsLoading(true); // Show loading indicator

    try {
      // --- API Call to Backend ---
      const backendApiUrl = process.env.REACT_APP_BACKEND_API_URL || 'http://127.0.0.1:8000'; // Fallback for local dev
      const response = await fetch(`${backendApiUrl}/chat_api/chat`, { // Corrected path to include /chat_api
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          user_id: userId,
          query_text: trimmedMessage,
          language: language,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to get response from bot.');
      }

      const data = await response.json();
      console.log('Backend response:', data);

      setMessages((prevMessages) => [
        ...prevMessages,
        { sender: 'bot', text: data.bot_response, timestamp: new Date() }
      ]);
      speakText(data.bot_response);

      if (data.status === 'unanswered') {
        console.log("Query was unanswered, needs escalation/review.");
        // You might add a visual cue for the user here, e.g., "Our team has been notified."
      }

    } catch (error) {
      console.error('Error communicating with backend:', error);
      setMessages((prevMessages) => [
        ...prevMessages,
        { sender: 'system', text: getSystemMessage('api_error', language), timestamp: new Date() }
      ]);
      speakText(getSystemMessage('api_error', language));
    } finally {
      setIsLoading(false); // Hide loading indicator
    }
  };

  // Function to toggle speech recognition
  const toggleListening = () => {
    if (SpeechRecognition) {
      if (isListening) {
        recognitionRef.current.stop();
      } else {
        if (window.speechSynthesis.speaking) {
          window.speechSynthesis.cancel();
        }
        recognitionRef.current.start();
      }
    } else {
      setMessages((prevMessages) => [
        ...prevMessages,
        { sender: 'system', text: getSystemMessage('browser_support_warning', language), timestamp: new Date() }
      ]);
    }
  };

  // Function to handle language change
  const handleLanguageChange = (e) => {
    const newLang = e.target.value;
    setLanguage(newLang);
    if (recognitionRef.current) {
      recognitionRef.current.lang = getSpeechRecognitionLangCode(newLang);
    }
    if (window.speechSynthesis.speaking) {
      window.speechSynthesis.cancel();
    }
    const confirmationText = newLang === 'en' ? "Language set to English." : (newLang === 'hi' ? "भाषा हिंदी पर सेट की गई है।" : "भाषा हिंग्लिश पर सेट की गई है।");
    speakText(confirmationText);
    setMessages((prevMessages) => [
      ...prevMessages,
      { sender: 'system', text: confirmationText, timestamp: new Date() }
    ]);
  };

  return (
    <Router>
      <div className="flex flex-col h-screen bg-gray-100 font-inter antialiased">
        <nav className="bg-gray-200 p-2 flex justify-end">
          <Link to="/" className="mr-4 text-blue-700 font-semibold">Chatbot</Link>
          <Link to="/admin" className="text-blue-700 font-semibold">Admin Dashboard</Link>
        </nav>
        <Routes>
          <Route path="/" element={
            <>
              {/* Header */}
              <header className="bg-blue-700 text-white p-4 shadow rounded-b-lg">
                <h1 className="text-3xl font-bold text-center">Kaamgar Sahayak</h1>
                <p className="text-center text-sm mt-1 opacity-90">Your AI Assistant for Labour Information in MP, India</p>
              </header>
              {/* Chat Window */}
              <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
                {messages.map((msg, index) => (
                  <div
                    key={index}
                    className={`flex ${msg.sender === 'user' ? 'justify-end' : (msg.sender === 'bot' ? 'justify-start' : 'justify-center')}`}
                  >
                    <div
                      className={`max-w-xs md:max-w-md lg:max-w-lg p-3 rounded-lg shadow-md ${
                        msg.sender === 'user'
                          ? 'bg-blue-500 text-white rounded-br-none'
                          : msg.sender === 'bot'
                          ? 'bg-white text-gray-800 rounded-bl-none'
                          : 'bg-gray-300 text-gray-700 text-center text-xs rounded-full px-4 py-1' // System messages
                      }`}
                    >
                      <p className="text-sm">{msg.text}</p>
                      {msg.sender !== 'system' && (
                        <span className="text-xs opacity-75 mt-1 block">
                          {msg.timestamp.toLocaleTimeString()}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
                {isLoading && (
                  <div className="flex justify-start">
                    <div className="bg-white text-gray-800 p-3 rounded-lg shadow-md rounded-bl-none">
                      <div className="flex space-x-1">
                        <div className="w-2 h-2 bg-gray-500 rounded-full animate-bounce" style={{ animationDelay: '0s' }}></div>
                        <div className="w-2 h-2 bg-gray-500 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                        <div className="w-2 h-2 bg-gray-500 rounded-full animate-bounce" style={{ animationDelay: '0.4s' }}></div>
                      </div>
                    </div>
                  </div>
                )}
                <div ref={messagesEndRef} />
              </div>
              {/* Input Area */}
              <div className="bg-white p-4 border-t border-gray-200 shadow-lg rounded-t-xl">
                {/* Language Selector */}
                <div className="mb-3 flex justify-center">
                  <select
                    value={language}
                    onChange={handleLanguageChange}
                    className="p-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500 text-sm"
                  >
                    <option value="en">English</option>
                    <option value="hi">हिंदी (Hindi)</option>
                  </select>
                </div>
                <div className="flex items-center space-x-3">
                  <input
                    type="text"
                    className="flex-1 p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-800"
                    placeholder={language === 'en' ? "Type your message..." : "अपना संदेश टाइप करें..."}
                    value={inputText}
                    onChange={(e) => setInputText(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
                    disabled={isLoading}
                  />
                  <button
                    onClick={toggleListening}
                    className={`p-3 rounded-full shadow-md transition-all duration-200 ease-in-out
                      ${isListening ? 'bg-red-500 hover:bg-red-600' : 'bg-blue-500 hover:bg-blue-600'}
                      text-white focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500
                      ${isLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
                    title={isListening ? "Stop Listening" : "Start Voice Input"}
                    disabled={isLoading}
                  >
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      className="h-6 w-6"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M19 11a7 7 0 01-14 0v-1a7 7 0 0114 0v1z"
                      />
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M12 20v-4m0 0H8m4 0h4m-4-8V4m0 0h4m-4 0H8"
                      />
                    </svg>
                  </button>
                  <button
                    onClick={() => handleSendMessage()}
                    className={`p-3 rounded-full bg-green-500 text-white shadow-md hover:bg-green-600 transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500
                      ${isLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
                    title="Send Message"
                    disabled={isLoading}
                  >
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      className="h-6 w-6"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M14 5l7 7m0 0l-7 7m7-7H3"
                      />
                    </svg>
                  </button>
                </div>
              </div>
              <style>
                {`
                  body {
                    font-family: 'Inter', sans-serif;
                    background: #f8fafc;
                  }
                  .custom-scrollbar::-webkit-scrollbar {
                    width: 8px;
                  }
                  .custom-scrollbar::-webkit-scrollbar-track {
                    background: #f1f1f1;
                    border-radius: 10px;
                  }
                  .custom-scrollbar::-webkit-scrollbar-thumb {
                    background: #888;
                    border-radius: 10px;
                  }
                  .custom-scrollbar::-webkit-scrollbar-thumb:hover {
                    background: #555;
                  }
                  @keyframes bounce {
                    0%, 100% { transform: translateY(-25%); animation-timing-function: cubic-bezier(0.8,0,1,1); }
                    50% { transform: translateY(0); animation-timing-function: cubic-bezier(0,0,0.2,1); }
                  }
                  .animate-bounce {
                    animation: bounce 1s infinite;
                  }
                `}
              </style>
            </>
          } />
          <Route path="/admin" element={<AdminDashboard />} />
        </Routes>
      </div>
    </Router>
  )
}

export default App;