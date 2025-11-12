import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import './ConversationsList.css';

function ConversationsList() {
  const [conversations, setConversations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Mock data for now - replace with API call later
  const mockConversations = [
    {
      with: 'alice12345678901234567890123456789012', // 32-char hex pubkey
      lastMessageTime: Date.now() - 3600000, // 1 hour ago
      messageCount: 5,
      lastMessagePreview: 'Hey, how are you doing?'
    },
    {
      with: 'bob456789012345678901234567890123456789',
      lastMessageTime: Date.now() - 86400000, // 1 day ago
      messageCount: 12,
      lastMessagePreview: 'Thanks for the help!'
    },
    {
      with: 'charlie78901234567890123456789012345678',
      lastMessageTime: Date.now() - 604800000, // 1 week ago
      messageCount: 3,
      lastMessagePreview: 'See you later'
    }
  ];

  useEffect(() => {
    // Simulate API call
    setTimeout(() => {
      setConversations(mockConversations);
      setLoading(false);
    }, 1000);
  }, []);

  const formatTime = (timestamp) => {
    const now = Date.now();
    const diff = now - timestamp;

    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    if (diff < 604800000) return `${Math.floor(diff / 86400000)}d ago`;

    return new Date(timestamp).toLocaleDateString();
  };

  const shortenPubkey = (pubkey) => {
    if (!pubkey) return 'Unknown';
    return `${pubkey.slice(0, 8)}...${pubkey.slice(-8)}`;
  };

  if (loading) {
    return (
      <div className="conversations-list">
        <div className="conversations-header">
          <h2>Conversations</h2>
          <Link to="/keys" className="keys-button">Keys</Link>
        </div>
        <div className="loading">Loading conversations...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="conversations-list">
        <div className="conversations-header">
          <h2>Conversations</h2>
          <Link to="/keys" className="keys-button">Keys</Link>
        </div>
        <div className="error">Error loading conversations: {error}</div>
      </div>
    );
  }

  return (
    <div className="conversations-list">
      <div className="conversations-header">
        <h2>Conversations</h2>
        <div className="header-actions">
          <Link to="/demo" className="demo-button">🔐 Demo</Link>
          <Link to="/keys" className="keys-button">Keys</Link>
        </div>
      </div>

      <div className="conversations-container">
        {conversations.length === 0 ? (
          <div className="empty-state">
            <p>No conversations yet.</p>
            <p>Start chatting with someone!</p>
          </div>
        ) : (
          conversations.map((conv) => (
            <Link
              key={conv.with}
              to={`/conversation/${conv.with}`}
              className="conversation-item"
            >
              <div className="conversation-avatar">
                {shortenPubkey(conv.with).charAt(0).toUpperCase()}
              </div>
              <div className="conversation-content">
                <div className="conversation-header">
                  <span className="conversation-name">
                    {shortenPubkey(conv.with)}
                  </span>
                  <span className="conversation-time">
                    {formatTime(conv.lastMessageTime)}
                  </span>
                </div>
                <div className="conversation-preview">
                  {conv.lastMessagePreview}
                </div>
                <div className="conversation-meta">
                  {conv.messageCount} messages
                </div>
              </div>
            </Link>
          ))
        )}
      </div>
    </div>
  );
}

export default ConversationsList;
