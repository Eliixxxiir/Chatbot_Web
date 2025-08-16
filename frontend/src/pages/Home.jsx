// import React from 'react';
// import { useNavigate } from 'react-router-dom';
// import '../styles/Home.css';

// const Home = () => {
//   const navigate = useNavigate();

//   const handleChatbotClick = () => {
//     navigate('/chatbot');
//   };

//   const handleFeedbackSubmit = (e) => {
//     e.preventDefault();
//     alert('आपकी प्रतिक्रिया के लिए धन्यवाद!');
//   };

//   return (
//     <div className="home-container">
//       <section className="hero-section">
//         <h1>श्रमजीवी सेवा पोर्टल में आपका स्वागत है</h1>
//         <p>श्रम नीतियों, योजनाओं और आपके अधिकारों की जानकारी पाएं</p>
//       </section>

//       <section className="info-section">
//         <div className="info-card">
//           <h2>श्रम नीतियाँ</h2>
//           <ol>
//             <li>व्यावसायिक सुरक्षा और स्वास्थ्य नीति</li>
//             <li>न्यूनतम वेतन नीति</li>
//             <li>सामाजिक सुरक्षा नीति</li>
//             <li>बच्चों के श्रम निषेध नीति</li>
//             <li>महिला श्रमिक कल्याण नीति</li>
//           </ol>
//         </div>

//         <div className="info-card">
//           <h2>सरकारी योजनाएँ</h2>
//           <ol>
//             <li>प्रधानमंत्री श्रम योगी मानधन योजना</li>
//             <li>आत्मनिर्भर भारत रोजगार योजना</li>
//             <li>कर्मचारी भविष्य निधि योजना</li>
//             <li>ई-श्रम कार्ड योजना</li>
//             <li>राष्ट्रीय पेंशन योजना (NPS)</li>
//           </ol>
//         </div>

//         <div className="info-card">
//           <h2>श्रमिक अधिकार</h2>
//           <ol>
//             <li>न्यूनतम वेतन पाने का अधिकार</li>
//             <li>समान कार्य हेतु समान वेतन</li>
//             <li>सुरक्षित कार्यस्थल का अधिकार</li>
//             <li>काम के घंटे और अवकाश का अधिकार</li>
//             <li>भविष्य निधि और पेंशन का अधिकार</li>
//           </ol>
//         </div>

//         <div className="info-card chatbot-card" onClick={handleChatbotClick}>
//           <h2>कोई प्रश्न है? हमारे चैटबॉट से पूछें!</h2>
//           <ol>
//             <li>योजना संबंधित जानकारी</li>
//             <li>दस्तावेज़ और प्रमाणपत्रों की जानकारी</li>
//             <li>शिकायत दर्ज कराने की प्रक्रिया</li>
//             <li>आपके अधिकारों पर मार्गदर्शन</li>
//             <li>ई-श्रम पंजीकरण सहायता</li>
//           </ol>
//         </div>
//       </section>

//       <section className="feedback-section">
//         <h2>अपनी प्रतिक्रिया दें</h2>
//         <form onSubmit={handleFeedbackSubmit} className="feedback-form">
//           <textarea placeholder="अपनी प्रतिक्रिया यहाँ लिखें..." required></textarea>
//           <div style={{ display: 'flex', justifyContent: 'center' }}>
//             <button type="submit">प्रस्तुत करें</button>
//           </div>
//         </form>
//       </section>
//     </div>
//   );
// };

// export default Home;
import React from 'react';
import { useNavigate } from 'react-router-dom';
import '../styles/Home.css';

const Home = ({ language }) => {
  const navigate = useNavigate();

  const content = {
    hi: {
      welcome: 'कामगार सहायक पोर्टल में आपका स्वागत है',
      subtitle: 'श्रम नीतियों, योजनाओं और आपके अधिकारों की जानकारी पाएं',
      feedback: 'अपनी प्रतिक्रिया दें',
      submit: 'प्रस्तुत करें',
      chatbotTitle: 'कोई प्रश्न है? हमारे चैटबॉट से पूछें!',
      feedbackPlaceholder: 'अपनी प्रतिक्रिया यहाँ लिखें...',
      policies: ['व्यावसायिक सुरक्षा और स्वास्थ्य नीति', 'न्यूनतम वेतन नीति', 'सामाजिक सुरक्षा नीति', 'बच्चों के श्रम निषेध नीति', 'महिला श्रमिक कल्याण नीति'],
      schemes: ['प्रधानमंत्री श्रम योगी मानधन योजना', 'आत्मनिर्भर भारत रोजगार योजना', 'कर्मचारी भविष्य निधि योजना', 'ई-श्रम कार्ड योजना', 'राष्ट्रीय पेंशन योजना (NPS)'],
      rights: ['न्यूनतम वेतन पाने का अधिकार', 'समान कार्य हेतु समान वेतन', 'सुरक्षित कार्यस्थल का अधिकार', 'काम के घंटे और अवकाश का अधिकार', 'भविष्य निधि और पेंशन का अधिकार'],
      chatbotHelp: ['योजना संबंधित जानकारी', 'दस्तावेज़ और प्रमाणपत्रों की जानकारी', 'शिकायत दर्ज कराने की प्रक्रिया', 'आपके अधिकारों पर मार्गदर्शन', 'ई-श्रम पंजीकरण सहायता']
    },
    en: {
      welcome: 'Welcome to the Kamgar Sahayak Portal',
      subtitle: 'Get information about labour policies, schemes, and your rights',
      feedback: 'Give Your Feedback',
      submit: 'Submit',
      chatbotTitle: 'Have a Question? Ask our Chatbot!',
      feedbackPlaceholder: 'Write your feedback here...',
      policies: ['Occupational Safety and Health Policy', 'Minimum Wage Policy', 'Social Security Policy', 'Child Labour Prohibition Policy', 'Women Worker Welfare Policy'],
      schemes: ['PM Shram Yogi Maandhan Scheme', 'Atmanirbhar Bharat Employment Scheme', 'Employee Provident Fund Scheme', 'E-Shram Card Scheme', 'National Pension Scheme (NPS)'],
      rights: ['Right to Minimum Wage', 'Equal Pay for Equal Work', 'Right to a Safe Workplace', 'Right to Work Hours and Leave', 'Right to Provident Fund and Pension'],
      chatbotHelp: ['Scheme-related Information', 'Documents and Certificates Info', 'Grievance Registration Process', 'Guidance on Your Rights', 'E-Shram Registration Assistance']
    }
  };

  const lang = content[language];

  const handleChatbotClick = () => {
    navigate('/chatbot');
  };

  const handleFeedbackSubmit = (e) => {
    e.preventDefault();
    alert(language === 'hi' ? 'आपकी प्रतिक्रिया के लिए धन्यवाद!' : 'Thank you for your feedback!');
  };

  return (
    <div className="home-container">
      <section className="hero-section">
        <h1>{lang.welcome}</h1>
        <p>{lang.subtitle}</p>
      </section>

      <section className="info-section">
        <div className="info-card">
          <h2>{language === 'hi' ? 'श्रम नीतियाँ' : 'Labour Policies'}</h2>
          <ol>
            {lang.policies.map((item, index) => <li key={index}>{item}</li>)}
          </ol>
        </div>

        <div className="info-card">
          <h2>{language === 'hi' ? 'सरकारी योजनाएँ' : 'Government Schemes'}</h2>
          <ol>
            {lang.schemes.map((item, index) => <li key={index}>{item}</li>)}
          </ol>
        </div>

        <div className="info-card">
          <h2>{language === 'hi' ? 'श्रमिक अधिकार' : 'Labour Rights'}</h2>
          <ol>
            {lang.rights.map((item, index) => <li key={index}>{item}</li>)}
          </ol>
        </div>

        <div className="info-card chatbot-card" onClick={handleChatbotClick}>
          <h2>{lang.chatbotTitle}</h2>
          <ol>
            {lang.chatbotHelp.map((item, index) => <li key={index}>{item}</li>)}
          </ol>
        </div>
      </section>

      <section className="feedback-section">
        <h2>{lang.feedback}</h2>
        <form onSubmit={handleFeedbackSubmit} className="feedback-form">
          <textarea placeholder={lang.feedbackPlaceholder} required></textarea>
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <button type="submit">{lang.submit}</button>
          </div>
        </form>
      </section>
    </div>
  );
};

export default Home;
