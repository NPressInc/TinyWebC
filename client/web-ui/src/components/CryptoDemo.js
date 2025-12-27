import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { keyStore, encryptPayloadMulti, decryptPayload } from '../utils';
import { createDirectMessage, verifyMessageSignature } from '../utils/message';
import { serializeMessageToProtobufHex, deserializeMessageFromProtobuf } from '../utils/messageHelper';
import './CryptoDemo.css';

function CryptoDemo() {
  const [aliceKey, setAliceKey] = useState('');
  const [bobKey, setBobKey] = useState('');
  const [charlieKey, setCharlieKey] = useState('');
  const [bobKeypair, setBobKeypair] = useState(null); // Store Bob's full keypair for decryption
  const [charlieKeypair, setCharlieKeypair] = useState(null); // Store Charlie's full keypair for decryption
  const [message, setMessage] = useState('Hello from Alice! This is a secret message.');
  const [encryptedHex, setEncryptedHex] = useState('');
  const [decryptedMessage, setDecryptedMessage] = useState('');
  const [decryptedByCharlie, setDecryptedByCharlie] = useState('');
  const [messageHex, setMessageHex] = useState('');
  const [verificationResult, setVerificationResult] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [multiRecipient, setMultiRecipient] = useState(false);

  useEffect(() => {
    initializeDemo();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const initializeDemo = async () => {
    try {
      setLoading(true);
      setError('');

      // Initialize keystore
      await keyStore.init();

      // Generate Alice's key (sender)
      await keyStore.generateKeypair();
      setAliceKey(keyStore.getPublicKeyHex());

      // Generate Bob's key (recipient) - in real app this would be imported
      const bobKeypair = await generateKeypairForDemo();
      setBobKey(bobKeypair.publicKeyHex);
      setBobKeypair(bobKeypair); // Store full keypair for decryption

      // Generate Charlie's key (second recipient)
      const charlieKeypair = await generateKeypairForDemo();
      setCharlieKey(charlieKeypair.publicKeyHex);
      setCharlieKeypair(charlieKeypair); // Store full keypair for decryption

    } catch (err) {
      setError('Failed to initialize demo: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const generateKeypairForDemo = async () => {
    // Generate a keypair for Bob (recipient)
    const keypair = await keyStore._generateKeypairForDemo();
    return {
      publicKey: keypair.publicKey,
      publicKeyHex: await keyStore._keyToHex(keypair.encryptionPublicKey), // Use X25519 key for display
      privateKey: keypair.privateKey,
      encryptionPublicKey: keypair.encryptionPublicKey, // X25519 public key for encryption
      encryptionPrivateKey: keypair.encryptionPrivateKey // X25519 private key for decryption
    };
  };

  const handleEncrypt = async () => {
    if (!message.trim()) {
      setError('Please enter a message to encrypt');
      return;
    }

    try {
      setLoading(true);
      setError('');

      // Convert message to bytes
      const plaintext = new TextEncoder().encode(message);

      // Use Bob's X25519 encryption public key (and Charlie's if multi-recipient mode)
      if (!bobKeypair || !bobKeypair.encryptionPublicKey) {
        throw new Error('Bob\'s keypair not available');
      }
      
      // Build recipient list
      const recipients = [bobKeypair.encryptionPublicKey];
      if (multiRecipient && charlieKeypair && charlieKeypair.encryptionPublicKey) {
        recipients.push(charlieKeypair.encryptionPublicKey);
      }
      
      // Encrypt for recipient(s)
      const encrypted = await encryptPayloadMulti(plaintext, recipients);

      // Convert to hex for display
      const encryptedHex = await keyStore._payloadToHex(encrypted);
      setEncryptedHex(encryptedHex);

      console.log('Message encrypted successfully');

    } catch (err) {
      setError('Encryption failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDecrypt = async () => {
    if (!encryptedHex) {
      setError('No encrypted message to decrypt');
      return;
    }

    try {
      setLoading(true);
      setError('');

      // Convert hex back to payload
      const encrypted = await keyStore._hexToPayload(encryptedHex);

      // Decrypt using Bob's private key (since message was encrypted for Bob)
      if (!bobKeypair || !bobKeypair.encryptionPublicKey || !bobKeypair.encryptionPrivateKey) {
        throw new Error('Bob\'s keypair not available');
      }
      
      // Build recipient list (must match the array used during encryption)
      const recipients = [bobKeypair.encryptionPublicKey];
      if (multiRecipient && charlieKeypair && charlieKeypair.encryptionPublicKey) {
        recipients.push(charlieKeypair.encryptionPublicKey);
      }
      
      // Decrypt with Bob's key
      const decryptedBytes = await decryptPayload(encrypted, recipients, bobKeypair.encryptionPrivateKey, bobKeypair.encryptionPublicKey);

      // Convert back to string
      const decryptedText = new TextDecoder().decode(decryptedBytes);
      setDecryptedMessage(decryptedText);

      console.log('Message decrypted successfully');

    } catch (err) {
      setError('Decryption failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateMessage = async () => {
    if (!message.trim()) {
      setError('Please enter a message');
      return;
    }

    try {
      setLoading(true);
      setError('');

      // Use Bob's Ed25519 public key for message creation
      if (!bobKeypair || !bobKeypair.publicKey) {
        throw new Error('Bob\'s keypair not available');
      }

      console.log('📝 Creating message...');
      console.log('👤 Bob publicKey (Ed25519):', bobKeypair.publicKey);
      console.log('👤 Bob publicKey type:', bobKeypair.publicKey?.constructor?.name);
      console.log('👤 Bob publicKey length:', bobKeypair.publicKey?.length);

      // Create signed message (uses Ed25519 key for signing)
      const msg = await createDirectMessage(bobKeypair.publicKey, message);
      console.log('✅ Message created:', msg);
      console.log('📋 Message header:', msg.header);
      console.log('👤 Message sender pubkey:', msg.header.senderPubkey);
      console.log('👤 Message sender pubkey type:', msg.header.senderPubkey?.constructor?.name);

      // Serialize to protobuf and convert to hex for display
      const messageHex = await serializeMessageToProtobufHex(msg);
      setMessageHex(messageHex);

      console.log('✅ Message serialized to hex');

    } catch (err) {
      console.error('❌ Message creation error:', err);
      console.error('Stack trace:', err.stack);
      setError('Message creation failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDecryptByCharlie = async () => {
    if (!encryptedHex) {
      setError('No encrypted message to decrypt');
      return;
    }

    if (!multiRecipient) {
      setError('Multi-recipient mode is not enabled');
      return;
    }

    try {
      setLoading(true);
      setError('');

      // Convert hex back to payload
      const encrypted = await keyStore._hexToPayload(encryptedHex);

      // Decrypt using Charlie's private key
      if (!charlieKeypair || !charlieKeypair.encryptionPublicKey || !charlieKeypair.encryptionPrivateKey) {
        throw new Error('Charlie\'s keypair not available');
      }
      
      // Build recipient list (must match the array used during encryption)
      const recipients = [bobKeypair.encryptionPublicKey, charlieKeypair.encryptionPublicKey];
      
      // Decrypt with Charlie's key
      const decryptedBytes = await decryptPayload(encrypted, recipients, charlieKeypair.encryptionPrivateKey, charlieKeypair.encryptionPublicKey);

      // Convert back to string
      const decryptedText = new TextDecoder().decode(decryptedBytes);
      setDecryptedByCharlie(decryptedText);

      console.log('Message decrypted by Charlie successfully');

    } catch (err) {
      setError('Decryption by Charlie failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyMessage = async () => {
    if (!messageHex) {
      setError('No message to verify');
      return;
    }

    try {
      setLoading(true);
      setError('');

      // Convert hex back to message
      console.log('🔍 Deserializing message from hex...');
      const msg = await deserializeMessageFromProtobuf(messageHex);
      console.log('📦 Message:', msg);
      console.log('📋 Header:', msg.header);
      console.log('👤 Sender pubkey type:', msg.header.senderPubkey?.constructor?.name);
      console.log('👤 Sender pubkey length:', msg.header.senderPubkey?.length);
      console.log('👤 Sender pubkey:', msg.header.senderPubkey);
      console.log('🔑 Signature type:', msg.signature?.constructor?.name);
      console.log('🔑 Signature length:', msg.signature?.length);

      // Verify signature
      console.log('✅ Verifying signature...');
      const isValid = await verifyMessageSignature(msg);

      setVerificationResult(isValid ? '✅ Signature is VALID' : '❌ Signature is INVALID');

    } catch (err) {
      console.error('❌ Verification error:', err);
      console.error('Stack trace:', err.stack);
      setError('Verification failed: ' + err.message);
      setVerificationResult('');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="crypto-demo">
      <div className="demo-header">
        <Link to="/" className="back-button">← Back to App</Link>
        <h2>🔐 Crypto Demo</h2>
      </div>

      {error && (
        <div className="error-banner">
          <span className="error-icon">⚠️</span>
          {error}
        </div>
      )}

      <div className="demo-content">
        <div className="demo-section">
          <h3>Keypairs</h3>
          <div className="key-display">
            <div className="key-item">
              <strong>Alice (Sender):</strong>
              <code>{aliceKey ? `${aliceKey.slice(0, 16)}...` : 'Not generated'}</code>
            </div>
            <div className="key-item">
              <strong>Bob (Recipient 1):</strong>
              <code>{bobKey ? `${bobKey.slice(0, 16)}...` : 'Not generated'}</code>
            </div>
            <div className="key-item">
              <strong>Charlie (Recipient 2):</strong>
              <code>{charlieKey ? `${charlieKey.slice(0, 16)}...` : 'Not generated'}</code>
            </div>
          </div>
          
          <div className="multi-recipient-toggle">
            <label>
              <input
                type="checkbox"
                checked={multiRecipient}
                onChange={(e) => setMultiRecipient(e.target.checked)}
              />
              <span>Enable Multi-Recipient Encryption (Bob + Charlie)</span>
            </label>
          </div>
        </div>

        <div className="demo-section">
          <h3>Message Encryption</h3>
          <div className="demo-form">
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Enter message to encrypt..."
              className="message-input"
              rows={3}
            />

            <div className="button-group">
              <button
                onClick={handleEncrypt}
                disabled={loading || !message.trim()}
                className="demo-button primary"
              >
                🔒 Encrypt
              </button>
            </div>

            {encryptedHex && (
              <div className="result-display">
                <h4>Encrypted (Hex):</h4>
                <code className="encrypted-hex">{encryptedHex.slice(0, 100)}...</code>
              </div>
            )}

            {encryptedHex && (
              <div className="button-group">
                <button
                  onClick={handleDecrypt}
                  disabled={loading}
                  className="demo-button secondary"
                >
                  🔓 Decrypt (Bob)
                </button>
                {multiRecipient && (
                  <button
                    onClick={handleDecryptByCharlie}
                    disabled={loading}
                    className="demo-button secondary"
                  >
                    🔓 Decrypt (Charlie)
                  </button>
                )}
              </div>
            )}

            {decryptedMessage && (
              <div className="result-display">
                <h4>Decrypted by Bob:</h4>
                <p className="decrypted-message">{decryptedMessage}</p>
              </div>
            )}

            {decryptedByCharlie && (
              <div className="result-display">
                <h4>Decrypted by Charlie:</h4>
                <p className="decrypted-message">{decryptedByCharlie}</p>
              </div>
            )}
          </div>
        </div>

        <div className="demo-section">
          <h3>Message Creation & Signing</h3>
          <div className="button-group">
            <button
              onClick={handleCreateMessage}
              disabled={loading || !message.trim()}
              className="demo-button primary"
            >
              ✉️ Create Signed Message
            </button>
          </div>

          {messageHex && (
            <div className="result-display">
              <h4>Message (Hex):</h4>
              <code className="message-hex">{messageHex.slice(0, 100)}...</code>
            </div>
          )}

          {messageHex && (
            <div className="button-group">
              <button
                onClick={handleVerifyMessage}
                disabled={loading}
                className="demo-button secondary"
              >
                ✅ Verify Signature
              </button>
            </div>
          )}

          {verificationResult && (
            <div className={`verification-result ${verificationResult.includes('VALID') ? 'valid' : 'invalid'}`}>
              {verificationResult}
            </div>
          )}
        </div>

        <div className="demo-info">
          <h3>How This Works</h3>
          <div className="info-content">
            <div className="info-item">
              <h4>🔐 Hybrid Encryption</h4>
              <p>AES-256-GCM encrypts message content, X25519 handles key exchange</p>
            </div>
            <div className="info-item">
              <h4>👥 Multi-Recipient</h4>
              <p>One message can be encrypted for multiple recipients efficiently</p>
            </div>
            <div className="info-item">
              <h4>✍️ Digital Signatures</h4>
              <p>Ed25519 signatures prove message authenticity and integrity</p>
            </div>
            <div className="info-item">
              <h4>🔄 Key Conversion</h4>
              <p>Ed25519 keys are converted to X25519 for encryption operations</p>
            </div>
            <div className="info-item">
              <h4>🔒 Forward Secrecy</h4>
              <p>Ephemeral keys ensure each message has unique encryption</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default CryptoDemo;
