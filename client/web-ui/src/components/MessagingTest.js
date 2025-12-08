import React, { useState, useEffect } from 'react';
import './MessagingTest.css';
import { detectRunningNodes, sendEnvelope, getRecentMessages, getMessages, DEFAULT_NODE_URLS } from '../utils/api';
import { createDirectMessage, CONTENT_TYPE } from '../utils/envelope';
import { serializeEnvelopeToProtobufHex } from '../utils/protobufHelper';
import keyStore from '../utils/keystore';
import sodium from 'libsodium-wrappers';

/**
 * MessagingTest component for manual testing of messaging between docker nodes
 * Allows testing parent-to-child, parent-to-parent, and message propagation scenarios
 */
function MessagingTest() {
  const [runningNodes, setRunningNodes] = useState([]);
  const [selectedNode, setSelectedNode] = useState('');
  const [selectedUser, setSelectedUser] = useState('');
  const [recipientPubkey, setRecipientPubkey] = useState('');
  const [messageText, setMessageText] = useState('');
  const [status, setStatus] = useState('');
  const [recentMessages, setRecentMessages] = useState([]);
  const [loading, setLoading] = useState(false);

  // Test users from network_config.json (these would need to be loaded from keys)
  const TEST_USERS = [
    { id: 'admin_001', name: 'John Smith (Parent)', role: 'admin' },
    { id: 'admin_002', name: 'Jane Smith (Parent)', role: 'admin' },
    { id: 'member_001', name: 'Emma Smith (Child, age 12)', role: 'member' },
    { id: 'member_002', name: 'Alex Smith (Child, age 8)', role: 'member' },
  ];

  useEffect(() => {
    detectRunningNodes().then(nodes => {
      setRunningNodes(nodes);
      if (nodes.length > 0) {
        setSelectedNode(nodes[0].url);
      }
    });
  }, []);

  const handleDetectNodes = async () => {
    setLoading(true);
    setStatus('Detecting running nodes...');
    try {
      const nodes = await detectRunningNodes();
      setRunningNodes(nodes);
      if (nodes.length > 0) {
        setSelectedNode(nodes[0].url);
        setStatus(`✓ Found ${nodes.length} running node(s)`);
      } else {
        setStatus('✗ No running nodes found. Make sure docker_test_runner.sh has started containers.');
      }
    } catch (error) {
      setStatus(`✗ Error: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!selectedNode || !messageText.trim() || !recipientPubkey.trim()) {
      setStatus('✗ Please fill in all fields');
      return;
    }

    setLoading(true);
    setStatus('Sending message...');

    try {
      await sodium.ready;
      await keyStore.init();

      // Check if keypair is loaded
      if (!keyStore.isKeypairLoaded()) {
        setStatus('✗ No keypair loaded. Please load or generate keys first.');
        setLoading(false);
        return;
      }

      // Convert recipient pubkey from hex to Uint8Array
      const recipientPubkeyBytes = sodium.from_hex(recipientPubkey.trim());

      // Create direct message envelope
      const envelope = await createDirectMessage(recipientPubkeyBytes, messageText);

      // Serialize envelope to protobuf format and hex-encode
      const envelopeHex = await serializeEnvelopeToProtobufHex(envelope);
      
      // Send to node
      const result = await sendEnvelope(selectedNode, envelopeHex);
      setStatus(`✓ Message sent! Status: ${result.status || 'success'}`);
      setMessageText('');
      
    } catch (error) {
      setStatus(`✗ Error sending message: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleGetRecentMessages = async () => {
    if (!selectedNode) {
      setStatus('✗ Please select a node');
      return;
    }

    setLoading(true);
    setStatus('Fetching recent messages...');

    try {
      const response = await getRecentMessages(selectedNode, 10);
      // Response contains envelope_list_hex which needs to be decoded
      setStatus(`✓ Found messages (envelope_list_hex: ${response.envelope_list_hex?.substring(0, 50)}...)`);
      // TODO: Decode protobuf envelope_list_hex and display messages
      setRecentMessages([]); // Placeholder
    } catch (error) {
      setStatus(`✗ Error fetching messages: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleLoadTestUserKey = async (userId) => {
    setLoading(true);
    setStatus(`Loading key for ${userId}...`);
    
    // TODO: Load user key from docker container or localStorage
    // For now, generate a test keypair
    try {
      await keyStore.init();
      await keyStore.generateKeypair();
      setStatus(`✓ Generated test keypair for ${userId} (public key: ${keyStore.getPublicKeyHex().substring(0, 16)}...)`);
      setSelectedUser(userId);
    } catch (error) {
      setStatus(`✗ Error loading key: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="messaging-test">
      <h2>Messaging Test Client</h2>
      <p>Test messaging between docker nodes. Make sure containers are running first.</p>

      <div className="test-section">
        <h3>1. Detect Running Nodes</h3>
        <button onClick={handleDetectNodes} disabled={loading}>
          Detect Nodes
        </button>
        {runningNodes.length > 0 && (
          <div className="nodes-list">
            <p>Running nodes:</p>
            <ul>
              {runningNodes.map((node, idx) => (
                <li key={idx}>
                  <label>
                    <input
                      type="radio"
                      name="node"
                      value={node.url}
                      checked={selectedNode === node.url}
                      onChange={(e) => setSelectedNode(e.target.value)}
                    />
                    {node.nodeId} ({node.url})
                  </label>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      <div className="test-section">
        <h3>2. Load Test User Key</h3>
        <p>Select a test user and load their keypair:</p>
        <div className="users-list">
          {TEST_USERS.map((user) => (
            <button
              key={user.id}
              onClick={() => handleLoadTestUserKey(user.id)}
              disabled={loading}
              className={selectedUser === user.id ? 'selected' : ''}
            >
              {user.name}
            </button>
          ))}
        </div>
        {keyStore.isKeypairLoaded() && (
          <p className="key-info">
            ✓ Keypair loaded (pubkey: {keyStore.getPublicKeyHex().substring(0, 32)}...)
          </p>
        )}
      </div>

      <div className="test-section">
        <h3>3. Send Message</h3>
        <form onSubmit={handleSendMessage}>
          <div className="form-group">
            <label>
              Target Node:
              <select
                value={selectedNode}
                onChange={(e) => setSelectedNode(e.target.value)}
                disabled={loading}
              >
                <option value="">Select a node</option>
                {runningNodes.map((node, idx) => (
                  <option key={idx} value={node.url}>
                    {node.nodeId} ({node.url})
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div className="form-group">
            <label>
              Recipient Public Key (hex):
              <input
                type="text"
                value={recipientPubkey}
                onChange={(e) => setRecipientPubkey(e.target.value)}
                placeholder="Enter 64-character hex public key"
                disabled={loading}
                maxLength={64}
              />
            </label>
          </div>

          <div className="form-group">
            <label>
              Message:
              <textarea
                value={messageText}
                onChange={(e) => setMessageText(e.target.value)}
                placeholder="Enter message text"
                disabled={loading}
                rows={3}
              />
            </label>
          </div>

          <button type="submit" disabled={loading || !selectedNode || !messageText.trim() || !recipientPubkey.trim()}>
            Send Message
          </button>
        </form>
      </div>

      <div className="test-section">
        <h3>4. View Recent Messages</h3>
        <button onClick={handleGetRecentMessages} disabled={loading || !selectedNode}>
          Get Recent Messages
        </button>
        {recentMessages.length > 0 && (
          <div className="messages-list">
            <p>Recent messages:</p>
            <ul>
              {recentMessages.map((msg, idx) => (
                <li key={idx}>{JSON.stringify(msg)}</li>
              ))}
            </ul>
          </div>
        )}
      </div>

      <div className="status-section">
        <h3>Status</h3>
        <div className="status-message">{status || 'Ready'}</div>
      </div>

      <div className="test-scenarios">
        <h3>Test Scenarios</h3>
        <p>Try these scenarios:</p>
        <ul>
          <li><strong>Parent → Child:</strong> Load admin_001 key, send to member_001 pubkey</li>
          <li><strong>Parent → Parent:</strong> Load admin_001 key, send to admin_002 pubkey</li>
          <li><strong>Message Propagation:</strong> Send message to node_01, check if it appears on node_02</li>
        </ul>
      </div>
    </div>
  );
}

export default MessagingTest;

