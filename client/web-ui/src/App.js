import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import './App.css';

// Components
import ConversationsList from './components/ConversationsList';
import ConversationView from './components/ConversationView';
import KeyManagement from './components/KeyManagement';
import CryptoDemo from './components/CryptoDemo';
import MessagingTest from './components/MessagingTest';
import AutoTestRunner from './components/AutoTestRunner';

function App() {
  return (
    <Router>
      <div className="App">
        <header className="App-header">
          <h1>TinyWeb Messenger</h1>
        </header>

        <main className="App-main">
          <Routes>
            <Route path="/" element={<ConversationsList />} />
            <Route path="/conversation/:userId" element={<ConversationView />} />
            <Route path="/keys" element={<KeyManagement />} />
            <Route path="/demo" element={<CryptoDemo />} />
            <Route path="/test" element={<MessagingTest />} />
            <Route path="/test/auto" element={<AutoTestRunner />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
