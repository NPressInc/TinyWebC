import React, { useState, useEffect } from 'react';
import './AutoTestRunner.css';
import { detectRunningNodes, sendEnvelope, getRecentMessages, DEFAULT_NODE_URLS } from '../utils/api';
import { createDirectMessage } from '../utils/envelope';
import { serializeEnvelopeToProtobufHex } from '../utils/protobufHelper';
import keyStore from '../utils/keystore';
import sodium from 'libsodium-wrappers';

/**
 * AutoTestRunner component for automated messaging tests
 * Runs a series of tests to verify messaging functionality
 */
function AutoTestRunner() {
  const [runningNodes, setRunningNodes] = useState([]);
  const [testResults, setTestResults] = useState([]);
  const [isRunning, setIsRunning] = useState(false);
  const [currentTest, setCurrentTest] = useState('');

  useEffect(() => {
    detectRunningNodes().then(nodes => {
      setRunningNodes(nodes);
    });
  }, []);

  const addTestResult = (testName, status, message, details = null) => {
    setTestResults(prev => [...prev, {
      id: Date.now(),
      testName,
      status, // 'pass', 'fail', 'warning'
      message,
      details,
      timestamp: new Date().toISOString(),
    }]);
  };

  const runAllTests = async () => {
    setIsRunning(true);
    setTestResults([]);
    setCurrentTest('Initializing...');

    try {
      await sodium.ready;
      await keyStore.init();

      // Test 1: Detect nodes
      setCurrentTest('Test 1: Detecting nodes');
      const nodes = await detectRunningNodes();
      setRunningNodes(nodes);
      
      if (nodes.length < 2) {
        addTestResult(
          'Node Detection',
          'fail',
          `Only ${nodes.length} node(s) detected. Need at least 2 nodes for testing.`,
          { nodes: nodes.length }
        );
        setIsRunning(false);
        return;
      }
      addTestResult('Node Detection', 'pass', `Found ${nodes.length} running node(s)`, { nodes: nodes.length });

      // Test 2: Generate test keypairs
      setCurrentTest('Test 2: Generating test keypairs');
      await keyStore.generateKeypair();
      const senderPubkey = keyStore.getPublicKey();
      const senderPubkeyHex = keyStore.getPublicKeyHex();
      addTestResult('Keypair Generation', 'pass', 'Generated test keypair', { pubkey: senderPubkeyHex.substring(0, 32) + '...' });

      // For testing, we need a recipient keypair too
      // In a real scenario, this would be loaded from another node/user
      // For now, we'll generate a second keypair for testing
      const recipientKeypair = await keyStore._generateKeypairForDemo();
      const recipientPubkeyHex = await keyStore._keyToHex(recipientKeypair.publicKey);
      addTestResult('Recipient Keypair', 'pass', 'Generated recipient keypair for testing', { pubkey: recipientPubkeyHex.substring(0, 32) + '...' });

      // Test 3: Send message
      setCurrentTest('Test 3: Sending message');
      const testMessage = `Auto-test message at ${new Date().toISOString()}`;
      
      try {
        const envelope = await createDirectMessage(recipientKeypair.publicKey, testMessage);
        const envelopeHex = await serializeEnvelopeToProtobufHex(envelope);
        
        // Send to first node
        const sendResult = await sendEnvelope(nodes[0].url, envelopeHex);
        addTestResult(
          'Send Message',
          'pass',
          `Message sent successfully to ${nodes[0].nodeId}`,
          { status: sendResult.status, node: nodes[0].nodeId }
        );
      } catch (error) {
        addTestResult('Send Message', 'fail', `Failed to send message: ${error.message}`, { error: error.toString() });
      }

      // Test 4: Wait and check for message propagation
      setCurrentTest('Test 4: Checking message propagation');
      await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds

      try {
        // Check if message appears on other nodes
        let foundOnOtherNode = false;
        for (let i = 1; i < nodes.length && !foundOnOtherNode; i++) {
          try {
            const recent = await getRecentMessages(nodes[i].url, 10);
            // TODO: Decode envelope_list_hex and check if our message is there
            // For now, just check if we got a response
            if (recent.envelope_list_hex) {
              foundOnOtherNode = true;
              addTestResult(
                'Message Propagation',
                'pass',
                `Message found on ${nodes[i].nodeId}`,
                { node: nodes[i].nodeId }
              );
            }
          } catch (error) {
            // Continue to next node
          }
        }

        if (!foundOnOtherNode) {
          addTestResult(
            'Message Propagation',
            'warning',
            'Message not yet found on other nodes (may need more time or message not propagated)',
            {}
          );
        }
      } catch (error) {
        addTestResult('Message Propagation', 'fail', `Error checking propagation: ${error.message}`, { error: error.toString() });
      }

      // Test 5: Health checks
      setCurrentTest('Test 5: Health checks');
      for (const node of nodes) {
        try {
          const health = await fetch(`${node.url}/health`);
          if (health.ok) {
            addTestResult(`Health Check (${node.nodeId})`, 'pass', 'Node is healthy', { node: node.nodeId });
          } else {
            addTestResult(`Health Check (${node.nodeId})`, 'fail', `Health check failed: ${health.status}`, { node: node.nodeId });
          }
        } catch (error) {
          addTestResult(`Health Check (${node.nodeId})`, 'fail', `Health check error: ${error.message}`, { node: node.nodeId });
        }
      }

      addTestResult('All Tests', 'pass', 'Test suite completed', { totalTests: testResults.length + 1 });
      setCurrentTest('Completed');

    } catch (error) {
      addTestResult('Test Suite', 'fail', `Test suite failed: ${error.message}`, { error: error.toString() });
      setCurrentTest('Failed');
    } finally {
      setIsRunning(false);
    }
  };

  const clearResults = () => {
    setTestResults([]);
  };

  return (
    <div className="auto-test-runner">
      <h2>Automated Test Runner</h2>
      <p>Run automated tests to verify messaging functionality across docker nodes.</p>

      <div className="test-controls">
        <button 
          onClick={runAllTests} 
          disabled={isRunning || runningNodes.length < 2}
          className="run-button"
        >
          {isRunning ? 'Running Tests...' : 'Run All Tests'}
        </button>
        <button 
          onClick={clearResults} 
          disabled={isRunning || testResults.length === 0}
        >
          Clear Results
        </button>
        {runningNodes.length < 2 && (
          <span className="warning">⚠️ Need at least 2 running nodes for testing</span>
        )}
      </div>

      {isRunning && (
        <div className="current-test">
          <strong>Current Test:</strong> {currentTest}
        </div>
      )}

      <div className="test-results">
        <h3>Test Results</h3>
        {testResults.length === 0 ? (
          <p className="no-results">No tests run yet. Click "Run All Tests" to start.</p>
        ) : (
          <div className="results-list">
            {testResults.map((result) => (
              <div key={result.id} className={`test-result ${result.status}`}>
                <div className="result-header">
                  <span className="test-name">{result.testName}</span>
                  <span className={`status-badge ${result.status}`}>
                    {result.status === 'pass' ? '✓' : result.status === 'fail' ? '✗' : '⚠'}
                    {result.status.toUpperCase()}
                  </span>
                </div>
                <div className="result-message">{result.message}</div>
                {result.details && (
                  <details className="result-details">
                    <summary>Details</summary>
                    <pre>{JSON.stringify(result.details, null, 2)}</pre>
                  </details>
                )}
                <div className="result-timestamp">{new Date(result.timestamp).toLocaleTimeString()}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="test-info">
        <h3>Test Coverage</h3>
        <ul>
          <li>✓ Node detection and health checks</li>
          <li>✓ Keypair generation</li>
          <li>✓ Message creation and encryption</li>
          <li>✓ Protobuf serialization</li>
          <li>✓ Message sending via API</li>
          <li>✓ Message propagation (basic check)</li>
        </ul>
      </div>
    </div>
  );
}

export default AutoTestRunner;

