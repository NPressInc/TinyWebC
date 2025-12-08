import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import './ConversationsList.css';
import { detectRunningNodes, getConversations, DEFAULT_NODE_URLS } from '../utils/api';
import { decodeConversationList } from '../utils/protobufDecode';
import keyStore from '../utils/keystore';

function ConversationsList() {
  const [conversations, setConversations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedNode, setSelectedNode] = useState('');
  const [availableNodes, setAvailableNodes] = useState([]);
  const [manualNodeUrl, setManualNodeUrl] = useState('');

  useEffect(() => {
    loadConversations();
  }, []);

  const loadConversations = async () => {
    setLoading(true);
    setError(null);

    try {
      // Detect running nodes
      const nodes = await detectRunningNodes();
      setAvailableNodes(nodes);
      
      // Use manual node URL if provided, otherwise use first detected node
      let nodeUrl = manualNodeUrl.trim() || (nodes.length > 0 ? nodes[0].url : '');
      
      if (!nodeUrl) {
        // Try default nodes as fallback
        const defaultNodes = Object.values(DEFAULT_NODE_URLS);
        nodeUrl = defaultNodes[0] || '';
        
        if (!nodeUrl) {
          setError('No running nodes detected. Please ensure:\n1. Docker containers are running (run docker_test_runner.sh)\n2. Containers are healthy\n3. Ports 8001-8004 are accessible\n\nYou can also manually enter a node URL below.\n\nCheck browser console (F12) for detailed error messages.');
          setLoading(false);
          return;
        }
      }
      
      setSelectedNode(nodeUrl);

      // Check if keypair is loaded
      if (!keyStore.isKeypairLoaded()) {
        setError('No keypair loaded. Please load or generate keys first.');
        setLoading(false);
        return;
      }

      // Get user's public key
      const userPubkey = keyStore.getPublicKeyHex();

      // Fetch conversations from API
      const response = await getConversations(nodeUrl, userPubkey);

      if (response.conversation_list_hex) {
        // Decode protobuf conversation list
        const decoded = await decodeConversationList(response.conversation_list_hex);
        
        // Transform to UI format
        const formatted = decoded.map(conv => ({
          with: conv.partnerPubkeyHex,
          lastMessageTime: conv.lastMessageTimestamp,
          messageCount: conv.unreadCount, // This might not be accurate, but it's what we have
          lastMessagePreview: conv.lastMessagePreview 
            ? 'Encrypted message' // Preview is encrypted, can't show actual text
            : 'No preview available',
        }));

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
        <h2>Conversations</h2>
        <div className="header-actions">
          <button onClick={loadConversations} className="refresh-button" disabled={loading}>
            {loading ? 'Loading...' : '🔄 Refresh'}
          </button>
          <Link to="/test" className="test-button">🧪 Test</Link>
          <Link to="/demo" className="demo-button">🔐 Demo</Link>
          <Link to="/keys" className="keys-button">Keys</Link>
        </div>
      </div>
      
      {availableNodes.length === 0 && (
        <div className="node-selection">
          <p>No nodes auto-detected. Manually enter node URL:</p>
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
