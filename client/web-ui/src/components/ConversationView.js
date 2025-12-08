import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import './ConversationView.css';
import { detectRunningNodes, getMessages, sendEnvelope, DEFAULT_NODE_URLS } from '../utils/api';
import { decodeEnvelopeList } from '../utils/protobufDecode';
import { createDirectMessage } from '../utils/envelope';
import { serializeEnvelopeToProtobufHex } from '../utils/protobufHelper';
import keyStore from '../utils/keystore';
import sodium from 'libsodium-wrappers';

function ConversationView() {
  const { userId } = useParams();
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [newMessage, setNewMessage] = useState('');
  const [sending, setSending] = useState(false);
  const [selectedNode, setSelectedNode] = useState('');

  useEffect(() => {
    loadMessages();
  }, [userId]);

  const loadMessages = async () => {
    setLoading(true);
    setError(null);

    try {
      // Detect running nodes
      const nodes = await detectRunningNodes();
      if (nodes.length === 0) {
        setError('No running nodes detected. Please start docker containers first.');
        setLoading(false);
        return;
      }

      const nodeUrl = nodes[0].url;
      setSelectedNode(nodeUrl);

      // Check if keypair is loaded
      if (!keyStore.isKeypairLoaded()) {
        setError('No keypair loaded. Please load or generate keys first.');
        setLoading(false);
        return;
      }

      // Get user's public key
      const userPubkey = keyStore.getPublicKeyHex();

      // Fetch messages from API
      const response = await getMessages(nodeUrl, userPubkey, userId);

      if (response.envelope_list_hex) {
        // Decode protobuf envelope list
        const decoded = await decodeEnvelopeList(response.envelope_list_hex);
        
        // Transform to UI format
        // Note: Messages are encrypted, so we can't show the actual content without decryption
        // For now, we'll show that messages exist but indicate they need decryption
        const formatted = decoded.map((env, idx) => {
          const isOutgoing = env.senderHex.toLowerCase() === userPubkey.toLowerCase();
          return {
            id: env.id,
            type: env.contentType,
            timestamp: env.timestamp,
            sender: env.senderHex,
            isOutgoing,
            // Message content is encrypted in the envelope, would need decryption to show
            // For now, show a placeholder
            content: '[Encrypted message - decryption not yet implemented in UI]',
          };
        });

        // Sort by timestamp (oldest first)
        formatted.sort((a, b) => a.timestamp - b.timestamp);
        
        setMessages(formatted);
      } else {
        setMessages([]);
      }
    } catch (err) {
      console.error('Error loading messages:', err);
      setError(err.message || 'Failed to load messages');
      setMessages([]);
    } finally {
      setLoading(false);
    }
  };

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

  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!newMessage.trim() || sending || !selectedNode) return;

    setSending(true);
    setError(null);

    try {
      await sodium.ready;
      await keyStore.init();

      if (!keyStore.isKeypairLoaded()) {
        setError('No keypair loaded. Please load or generate keys first.');
        setSending(false);
        return;
      }

      // Convert recipient pubkey from hex to Uint8Array
      const recipientPubkeyBytes = sodium.from_hex(userId);

      // Create direct message envelope
      const envelope = await createDirectMessage(recipientPubkeyBytes, newMessage);

      // Serialize to protobuf and hex-encode
      const envelopeHex = await serializeEnvelopeToProtobufHex(envelope);

      // Send to node
      const result = await sendEnvelope(selectedNode, envelopeHex);

      // Clear input
      setNewMessage('');

      // Reload messages to show the new one
      await loadMessages();
    } catch (err) {
      console.error('Error sending message:', err);
      setError(err.message || 'Failed to send message');
    } finally {
      setSending(false);
    }
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
          <button onClick={loadMessages} className="refresh-button" disabled={loading}>
            {loading ? '⏳' : '🔄'}
          </button>
          <button className="action-button">⋮</button>
        </div>
      </div>
      {selectedNode && (
        <div className="node-info">
          Connected to: {selectedNode}
        </div>
      )}

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
                {message.content || '[Message]'}
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
          disabled={!newMessage.trim() || sending || !selectedNode}
        >
          {sending ? 'Sending...' : 'Send'}
        </button>
      </form>
    </div>
  );
}

export default ConversationView;
