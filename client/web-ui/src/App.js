import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Link } from 'react-router-dom';
import './App.css';

// Components
import Login from './components/Login';
import ConversationsList from './components/ConversationsList';
import ConversationView from './components/ConversationView';
import KeyManagement from './components/KeyManagement';
import CryptoDemo from './components/CryptoDemo';
import LocationDashboard from './components/LocationDashboard';

// Auth utilities
import { isAuthenticated, setAuthState, clearAuthState } from './utils/auth';
import keyStore from './utils/keystore';

function App() {
  const [authenticated, setAuthenticated] = useState(false);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      // Check if user is logged in
      const loggedIn = isAuthenticated();
      
      if (loggedIn) {
        // Verify key is still loaded
        await keyStore.init();
        if (keyStore.isKeypairLoaded()) {
          setAuthenticated(true);
        } else {
          // Key not loaded, clear auth state
          clearAuthState();
          setAuthenticated(false);
        }
      } else {
        setAuthenticated(false);
      }
    } catch (err) {
      console.error('Auth check error:', err);
      clearAuthState();
      setAuthenticated(false);
    } finally {
      setChecking(false);
    }
  };

  const handleLoginSuccess = (pubkey, nodeUrl) => {
    setAuthState(pubkey, nodeUrl);
    setAuthenticated(true);
  };

  const handleLogout = () => {
    clearAuthState();
    keyStore.cleanup();
    setAuthenticated(false);
  };

  if (checking) {
    return (
      <div className="App">
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
          <p>Loading...</p>
        </div>
      </div>
    );
  }

  if (!authenticated) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <Router>
      <div className="App">
        <header className="App-header">
          <h1>TinyWeb Admin Dashboard</h1>
          <nav>
            <Link to="/">Messages</Link>
            <Link to="/locations">Locations</Link>
            <Link to="/keys">Keys</Link>
            <Link to="/demo">Crypto Demo</Link>
            <button onClick={handleLogout} className="logout-button">Logout</button>
          </nav>
        </header>

        <main className="App-main">
          <Routes>
            <Route path="/" element={<ConversationsList />} />
            <Route path="/conversation/:userId" element={<ConversationView />} />
            <Route path="/locations" element={<LocationDashboard />} />
            <Route path="/keys" element={<KeyManagement />} />
            <Route path="/demo" element={<CryptoDemo />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
