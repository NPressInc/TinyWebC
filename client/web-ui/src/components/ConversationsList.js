import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import './ConversationsList.css';
import { detectRunningNodes, getRecentMessages, getUsers, DEFAULT_NODE_URLS } from '../utils/api';
import { decodeEnvelopeList } from '../utils/protobufDecode';
import { deserializeEnvelopeFromProtobuf } from '../utils/protobufHelper';
import { decryptPayload } from '../utils/encryption';
import { calculateConversationId, getConversationIdFromEnvelope } from '../utils/conversationId';
import keyStore from '../utils/keystore';
import sodium from 'libsodium-wrappers';

function ConversationsList() {
  const navigate = useNavigate();
  const [conversations, setConversations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedNode, setSelectedNode] = useState('');
  const [availableNodes, setAvailableNodes] = useState([]);
  const [manualNodeUrl, setManualNodeUrl] = useState('');
  const [showNewConversation, setShowNewConversation] = useState(false);
  const [newConversationPubkey, setNewConversationPubkey] = useState('');
  const [users, setUsers] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(false);

  useEffect(() => {
    loadConversations();
  }, []);

  const loadUsers = async (nodeUrl) => {
    if (!nodeUrl) return;
    
    setLoadingUsers(true);
    try {
      const response = await getUsers(nodeUrl);
      if (response.users) {
        setUsers(response.users);
      }
    } catch (err) {
      console.error('Error loading users:', err);
      setUsers([]);
    } finally {
      setLoadingUsers(false);
    }
  };

  const loadConversations = async () => {
    setLoading(true);
    setError(null);

    try {
      // Initialize keystore and check for keys
      await keyStore.init();
      
      // Check if keypair is loaded
      if (!keyStore.isKeypairLoaded()) {
        setError('No keypair loaded. Please load or generate keys first.');
        setLoading(false);
        return;
      }

      // Always use first detected node (or first default node)
      const nodes = await detectRunningNodes();
      setAvailableNodes(nodes);
      
      // Use first detected node, or first default node as fallback
      let nodeUrl = nodes.length > 0 ? nodes[0].url : '';
      if (!nodeUrl) {
        const defaultNodes = Object.values(DEFAULT_NODE_URLS);
        nodeUrl = defaultNodes[0] || '';
      }
      
      if (!nodeUrl) {
        setError('No running nodes detected. Please ensure:\n1. Docker containers are running (run docker_test_runner.sh)\n2. Containers are healthy\n3. Ports 8001-8004 are accessible\n\nCheck browser console (F12) for detailed error messages.');
        setLoading(false);
        return;
      }
      
      setSelectedNode(nodeUrl);
      
      // Load users when node is selected
      if (nodeUrl) {
        loadUsers(nodeUrl);
      }

      // Ensure sodium is ready
      await sodium.ready;
      await keyStore.init();

      // Get user's public key
      const userPubkey = keyStore.getPublicKeyHex();
      const userPubkeyBytes = sodium.from_hex(userPubkey);

      // Fetch all recent messages for this user
      const response = await getRecentMessages(nodeUrl, userPubkey, 100);

      if (response.envelope_list_hex) {
        // Decode protobuf envelope list
        const decoded = await decodeEnvelopeList(response.envelope_list_hex);
        
        // Group messages by conversation_id and decrypt
        const conversationMap = new Map();
        
        for (const stored of decoded) {
          try {
            // Decode envelope from protobuf bytes
            const envelopeBytes = new Uint8Array(stored.envelope);
            const envelope = await deserializeEnvelopeFromProtobuf(envelopeBytes);
            
            // Calculate conversation_id
            const conversationId = await getConversationIdFromEnvelope(envelope, userPubkey);
            
            // Determine conversation partner
            const isOutgoing = sodium.memcmp(
              new Uint8Array(envelope.header.senderPubkey),
              userPubkeyBytes
            );
            
            let partnerPubkey;
            if (isOutgoing) {
              // We sent it, partner is the recipient
              partnerPubkey = envelope.header.recipientPubkeys[0];
            } else {
              // They sent it, partner is the sender
              partnerPubkey = envelope.header.senderPubkey;
            }
            
            const partnerHex = Array.from(partnerPubkey)
              .map(b => b.toString(16).padStart(2, '0'))
              .join('');
            
            // Decrypt message
            let messageText = '[Unable to decrypt]';
            try {
              const plaintext = await decryptPayload(
                envelope.encryptedPayload,
                envelope.header.recipientPubkeys
              );
              messageText = new TextDecoder().decode(plaintext);
            } catch (decryptErr) {
              console.warn('Failed to decrypt message:', decryptErr);
            }
            
            // Get or create conversation by conversation_id
            if (!conversationMap.has(conversationId)) {
              conversationMap.set(conversationId, {
                conversationId,
                with: partnerHex,
                messages: [],
                lastMessageTime: 0,
              });
            }
            
            const conv = conversationMap.get(conversationId);
            conv.messages.push({
              id: stored.id,
              text: messageText,
              timestamp: stored.timestamp,
              isOutgoing,
            });
            
            // Update last message time
            if (stored.timestamp > conv.lastMessageTime) {
              conv.lastMessageTime = stored.timestamp;
            }
          } catch (err) {
            console.error('Error processing envelope:', err);
          }
        }
        
        // Convert map to array and sort by last message time
        const formatted = Array.from(conversationMap.values())
          .map(conv => ({
            conversationId: conv.conversationId,
            with: conv.with,
            lastMessagePreview: conv.messages.length > 0 
              ? conv.messages[conv.messages.length - 1].text 
              : 'No messages',
            messageCount: conv.messages.length,
            lastMessageTime: conv.lastMessageTime,
          }))
          .sort((a, b) => b.lastMessageTime - a.lastMessageTime);

        setConversations(formatted);
      } else {
        setConversations([]);
      }
    } catch (err) {
      console.error('Error loading conversations:', err);
      setError(err.message || 'Failed to load conversations');
      setConversations([]);
    } finally {
      setLoading(false);
    }
  };

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
        <h2>Messages</h2>
        <div className="header-actions">
          <button 
            onClick={() => setShowNewConversation(!showNewConversation)} 
            className="new-conversation-button"
          >
            + New
          </button>
          <button onClick={loadConversations} className="refresh-button" disabled={loading}>
            {loading ? 'Loading...' : '🔄 Refresh'}
          </button>
          <Link to="/keys" className="keys-button">Keys</Link>
        </div>
      </div>
      
      {showNewConversation && (
        <div className="new-conversation-form">
          <h3>Start New Conversation</h3>
          {loadingUsers ? (
            <p>Loading users...</p>
          ) : users.length === 0 ? (
            <p>No users found. Make sure the node is connected.</p>
          ) : (
            <>
              <div style={{ marginTop: '10px' }}>
                <label htmlFor="user-select" style={{ display: 'block', marginBottom: '8px', fontWeight: '500' }}>
                  Select a user:
                </label>
                <select
                  id="user-select"
                  value={newConversationPubkey}
                  onChange={(e) => setNewConversationPubkey(e.target.value)}
                  style={{ 
                    width: '100%', 
                    padding: '8px', 
                    fontSize: '14px',
                    border: '1px solid #ddd',
                    borderRadius: '4px'
                  }}
                >
                  <option value="">-- Select a user --</option>
                  {users.map((user) => (
                    <option key={user.pubkey} value={user.pubkey}>
                      {user.username || 'Unknown'} {user.age ? `(${user.age})` : ''}
                    </option>
                  ))}
                </select>
              </div>
              <div style={{ display: 'flex', gap: '10px', marginTop: '10px' }}>
                <button
                  onClick={() => {
                    if (newConversationPubkey.trim()) {
                      navigate(`/conversation/${newConversationPubkey.trim()}`);
                    }
                  }}
                  disabled={!newConversationPubkey.trim()}
                  style={{ flex: 1 }}
                >
                  Start Conversation
                </button>
                <button onClick={() => {
                  setShowNewConversation(false);
                  setNewConversationPubkey('');
                }}>
                  Cancel
                </button>
              </div>
            </>
          )}
        </div>
      )}
      
      {!selectedNode && (
        <div className="node-selection">
          <p>No nodes detected. Manually enter node URL:</p>
          <div style={{ display: 'flex', gap: '10px', marginTop: '10px' }}>
            <input
              type="text"
              value={manualNodeUrl}
              onChange={(e) => setManualNodeUrl(e.target.value)}
              placeholder="http://localhost:8001"
              style={{ flex: 1, padding: '8px' }}
            />
            <button onClick={loadConversations} disabled={loading || !manualNodeUrl.trim()}>
              Connect
            </button>
          </div>
          <p style={{ fontSize: '12px', color: '#666', marginTop: '5px' }}>
            Try: http://localhost:8001, http://localhost:8002, etc.
          </p>
        </div>
      )}
      
      {selectedNode && (
        <div className="node-info">
          Connected to: {selectedNode}
          {availableNodes.length > 0 && (
            <span style={{ marginLeft: '10px', fontSize: '12px' }}>
              ({availableNodes.length} node{availableNodes.length !== 1 ? 's' : ''} detected)
            </span>
          )}
        </div>
      )}

      <div className="conversations-container">
        {conversations.length === 0 ? (
          <div className="empty-state">
            <p>No messages yet.</p>
            <p>Click "New" to start a conversation!</p>
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
                  {conv.lastMessagePreview.length > 50 
                    ? conv.lastMessagePreview.substring(0, 50) + '...'
                    : conv.lastMessagePreview}
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
