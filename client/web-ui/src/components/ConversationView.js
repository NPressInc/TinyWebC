import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import './ConversationView.css';

function ConversationView() {
  const { userId } = useParams();
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [newMessage, setNewMessage] = useState('');

  // Mock data for now - replace with API call later
  const mockMessages = [
    {
      id: 1,
      type: 1, // TW_TXN_MESSAGE
      timestamp: Date.now() - 3600000, // 1 hour ago
      sender: userId,
      isOutgoing: false,
      transaction_hex: '48656c6c6f2c20686f772061726520796f753f' // "Hello, how are you?" in hex
    },
    {
      id: 2,
      type: 1,
      timestamp: Date.now() - 3300000, // 55 minutes ago
      sender: 'your_pubkey_placeholder', // This would be the current user's key
      isOutgoing: true,
      transaction_hex: '49276d20646f696e672067726561742c207468616e6b73' // "I'm doing great, thanks" in hex
    },
    {
      id: 3,
      type: 1,
      timestamp: Date.now() - 1800000, // 30 minutes ago
      sender: userId,
      isOutgoing: false,
      transaction_hex: '476c616420746f2068656172207468617421' // "Glad to hear that!" in hex
    }
  ];

  useEffect(() => {
    // Simulate API call to fetch messages
    setTimeout(() => {
      setMessages(mockMessages);
      setLoading(false);
    }, 1000);
  }, [userId]);

  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const hexToString = (hex) => {
    try {
      // Convert hex to string (simplified - in reality would need proper decryption)
      let str = '';
      for (let i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
      }
      return str;
    } catch (e) {
      return hex; // Fallback to showing hex if conversion fails
    }
  };

  const handleSendMessage = (e) => {
    e.preventDefault();
    if (!newMessage.trim()) return;

    // Mock sending message - in reality this would encrypt and send to API
    const messageData = {
      content: newMessage,
      recipient: userId,
      timestamp: Date.now()
    };

    console.log('Sending message:', messageData);
    setNewMessage('');

    // Mock adding to UI immediately (would normally wait for API response)
    const newMsg = {
      id: Date.now(),
      type: 1,
      timestamp: Date.now(),
      sender: 'your_pubkey_placeholder',
      isOutgoing: true,
      transaction_hex: newMessage.split('').map(c => c.charCodeAt(0).toString(16)).join('') // Simple text to hex
    };

    setMessages(prev => [...prev, newMsg]);
  };

  const shortenPubkey = (pubkey) => {
    if (!pubkey) return 'Unknown';
    return `${pubkey.slice(0, 8)}...${pubkey.slice(-8)}`;
  };

  if (loading) {
    return (
      <div className="conversation-view">
        <div className="conversation-header">
          <Link to="/" className="back-button">← Back</Link>
          <h2>Loading conversation...</h2>
        </div>
        <div className="loading">Loading messages...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="conversation-view">
        <div className="conversation-header">
          <Link to="/" className="back-button">← Back</Link>
          <h2>Conversation with {shortenPubkey(userId)}</h2>
        </div>
        <div className="error">Error loading messages: {error}</div>
      </div>
    );
  }

  return (
    <div className="conversation-view">
      <div className="conversation-header">
        <Link to="/" className="back-button">← Back</Link>
        <h2>Conversation with {shortenPubkey(userId)}</h2>
        <div className="conversation-actions">
          <button className="action-button">⋮</button>
        </div>
      </div>

      <div className="messages-container">
        {messages.length === 0 ? (
          <div className="empty-messages">
            <p>No messages yet.</p>
            <p>Send the first message!</p>
          </div>
        ) : (
          messages.map((message) => (
            <div
              key={message.id}
              className={`message ${message.isOutgoing ? 'outgoing' : 'incoming'}`}
            >
              <div className="message-content">
                {hexToString(message.transaction_hex)}
              </div>
              <div className="message-time">
                {formatTime(message.timestamp)}
              </div>
            </div>
          ))
        )}
      </div>

      <form className="message-input-form" onSubmit={handleSendMessage}>
        <input
          type="text"
          value={newMessage}
          onChange={(e) => setNewMessage(e.target.value)}
          placeholder="Type a message..."
          className="message-input"
          maxLength={200}
        />
        <button
          type="submit"
          className="send-button"
          disabled={!newMessage.trim()}
        >
          Send
        </button>
      </form>
    </div>
  );
}

export default ConversationView;
