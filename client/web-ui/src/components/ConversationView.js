import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import './ConversationView.css';
import { detectRunningNodes, getMessages, sendMessage, DEFAULT_NODE_URLS } from '../utils/api';
import { createDirectMessage } from '../utils/message';
import { serializeMessageToProtobuf } from '../utils/messageHelper';
import { decryptPayload } from '../utils/encryption';
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
      // Initialize keystore first
      await keyStore.init();
      
      // Check if keypair is loaded
      if (!keyStore.isKeypairLoaded()) {
        setError('No keypair loaded. Please load or generate keys first.');
        setLoading(false);
        return;
      }

      // Always use first detected node (or first default node)
      const nodes = await detectRunningNodes();
      let nodeUrl = nodes.length > 0 ? nodes[0].url : '';
      if (!nodeUrl) {
        const defaultNodes = Object.values(DEFAULT_NODE_URLS);
        nodeUrl = defaultNodes[0] || '';
      }
      
      if (!nodeUrl) {
        setError('No running nodes detected. Please start docker containers first.');
        setLoading(false);
        return;
      }
      
      setSelectedNode(nodeUrl);

      // Ensure sodium is ready
      await sodium.ready;

      // Get user's public key
      const userPubkey = keyStore.getPublicKeyHex();
      const userPubkeyBytes = sodium.from_hex(userPubkey);

      // Fetch messages from API (now returns Message array directly)
      const messageList = await getMessages(nodeUrl, userPubkey, userId);

      // Decrypt and format messages
      const formatted = [];
      
      for (const message of messageList) {
        try {
          // Determine if message is outgoing
          const isOutgoing = sodium.memcmp(
            new Uint8Array(message.header.senderPubkey),
            userPubkeyBytes
          );
          
          // Convert recipient pubkeys to X25519 for decryption
          const encryptionPubkeys = message.header.recipientsPubkey.map(ed25519Pubkey => 
            sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519Pubkey)
          );
          
          // Decrypt message
          let messageText = '[Unable to decrypt]';
          try {
            const plaintext = await decryptPayload(
              message.encryptedPayload,
              encryptionPubkeys
            );
            messageText = new TextDecoder().decode(plaintext);
          } catch (decryptErr) {
            console.warn('Failed to decrypt message:', decryptErr);
          }
          
          // Convert sender pubkey to hex for display
          const senderHex = Array.from(message.header.senderPubkey)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
          
          // Convert timestamp from seconds to milliseconds
          const timestamp = message.header.timestamp * 1000;
          
          formatted.push({
            id: senderHex + '_' + timestamp, // Generate ID from sender and timestamp
            timestamp: timestamp,
            sender: senderHex,
            isOutgoing,
            content: messageText,
          });
        } catch (err) {
          console.error('Error processing message:', err);
          // Add error message as fallback
          const senderHex = Array.from(message.header.senderPubkey)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
          formatted.push({
            id: senderHex + '_' + (message.header.timestamp * 1000),
            timestamp: message.header.timestamp * 1000,
            sender: senderHex,
            isOutgoing: false,
            content: '[Error processing message]',
          });
        }
      }

      // Sort by timestamp (oldest first)
      formatted.sort((a, b) => a.timestamp - b.timestamp);
      
      setMessages(formatted);
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
    console.log('[handleSendMessage] Starting send, newMessage:', newMessage, 'sending:', sending, 'selectedNode:', selectedNode);
    
    if (!newMessage.trim() || sending || !selectedNode) {
      console.log('[handleSendMessage] Early return - validation failed');
      return;
    }

    setSending(true);
    setError(null);

    try {
      console.log('[handleSendMessage] Waiting for sodium...');
      await sodium.ready;
      console.log('[handleSendMessage] Initializing keystore...');
      await keyStore.init();

      if (!keyStore.isKeypairLoaded()) {
        console.error('[handleSendMessage] No keypair loaded');
        setError('No keypair loaded. Please load or generate keys first.');
        setSending(false);
        return;
      }

      console.log('[handleSendMessage] Converting recipient pubkey from hex:', userId);
      // Convert recipient pubkey from hex to Uint8Array
      const recipientPubkeyBytes = sodium.from_hex(userId);
      console.log('[handleSendMessage] Recipient pubkey bytes length:', recipientPubkeyBytes.length);

      console.log('[handleSendMessage] Creating direct message...');
      // Create direct message
      const message = await createDirectMessage(recipientPubkeyBytes, newMessage);
      console.log('[handleSendMessage] Message created:', message);

      console.log('[handleSendMessage] Sending message to node:', selectedNode);
      // Send to node (sends binary protobuf directly)
      const result = await sendMessage(selectedNode, message);
      console.log('[handleSendMessage] Send result:', result);

      // Clear input
      setNewMessage('');

      // Reload messages to show the new one
      console.log('[handleSendMessage] Reloading messages...');
      await loadMessages();
    } catch (err) {
      console.error('[handleSendMessage] Error sending message:', err);
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
          messages.map((message, index) => {
            // Group consecutive messages from same sender
            const prevMessage = index > 0 ? messages[index - 1] : null;
            const showAvatar = !prevMessage || 
              prevMessage.isOutgoing !== message.isOutgoing ||
              (message.timestamp - prevMessage.timestamp) > 300000; // 5 minutes
            
            return (
              <div
                key={message.id}
                className={`message-wrapper ${message.isOutgoing ? 'outgoing' : 'incoming'}`}
              >
                {!message.isOutgoing && showAvatar && (
                  <div className="message-avatar">
                    {shortenPubkey(message.sender).charAt(0).toUpperCase()}
                  </div>
                )}
                <div className={`message-bubble ${message.isOutgoing ? 'outgoing' : 'incoming'}`}>
                  <div className="message-content">
                    {message.content || '[Message]'}
                  </div>
                  <div className="message-time">
                    {formatTime(message.timestamp)}
                  </div>
                </div>
                {message.isOutgoing && showAvatar && (
                  <div className="message-avatar outgoing-avatar">
                    You
                  </div>
                )}
              </div>
            );
          })
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
