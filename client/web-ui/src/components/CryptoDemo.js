import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { keyStore, encryptPayloadMulti, decryptPayload, createDirectMessage, verifyEnvelopeSignature } from '../utils';
import './CryptoDemo.css';

function CryptoDemo() {
  const [aliceKey, setAliceKey] = useState('');
  const [bobKey, setBobKey] = useState('');
  const [message, setMessage] = useState('Hello from Alice! This is a secret message.');
  const [encryptedHex, setEncryptedHex] = useState('');
  const [decryptedMessage, setDecryptedMessage] = useState('');
  const [envelopeHex, setEnvelopeHex] = useState('');
  const [verificationResult, setVerificationResult] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    initializeDemo();
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
      publicKeyHex: await keyStore._keyToHex(keypair.publicKey),
      privateKey: keypair.privateKey
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

      // Convert Bob's public key from hex to bytes
      const bobPubkeyBytes = await keyStore._hexToKey(bobKey);

      // Encrypt for Bob
      const encrypted = await encryptPayloadMulti(plaintext, [bobPubkeyBytes]);

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

      // Convert Bob's public key (needed for decryption)
      const bobPubkeyBytes = await keyStore._hexToKey(bobKey);

      // Decrypt using Bob's "private key" (in demo we use Alice's for simplicity)
      const decryptedBytes = await decryptPayload(encrypted, bobPubkeyBytes);

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

  const handleCreateEnvelope = async () => {
    if (!message.trim()) {
      setError('Please enter a message to envelope');
      return;
    }

    try {
      setLoading(true);
      setError('');

      // Convert Bob's public key from hex to bytes
      const bobPubkeyBytes = await keyStore._hexToKey(bobKey);

      // Create signed envelope
      const envelope = await createDirectMessage(bobPubkeyBytes, message);

      // Convert to hex for display (simplified)
      const envelopeHex = await keyStore._envelopeToHex(envelope);
      setEnvelopeHex(envelopeHex);

      console.log('Envelope created successfully');

    } catch (err) {
      setError('Envelope creation failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyEnvelope = async () => {
    if (!envelopeHex) {
      setError('No envelope to verify');
      return;
    }

    try {
      setLoading(true);
      setError('');

      // Convert hex back to envelope
      const envelope = await keyStore._hexToEnvelope(envelopeHex);

      // Verify signature
      const isValid = await verifyEnvelopeSignature(envelope);

      setVerificationResult(isValid ? '✅ Signature is VALID' : '❌ Signature is INVALID');

    } catch (err) {
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
              <strong>Bob (Recipient):</strong>
              <code>{bobKey ? `${bobKey.slice(0, 16)}...` : 'Not generated'}</code>
            </div>
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
                  🔓 Decrypt
                </button>
              </div>
            )}

            {decryptedMessage && (
              <div className="result-display">
                <h4>Decrypted:</h4>
                <p className="decrypted-message">{decryptedMessage}</p>
              </div>
            )}
          </div>
        </div>

        <div className="demo-section">
          <h3>Envelope Creation & Signing</h3>
          <div className="button-group">
            <button
              onClick={handleCreateEnvelope}
              disabled={loading || !message.trim()}
              className="demo-button primary"
            >
              ✉️ Create Signed Envelope
            </button>
          </div>

          {envelopeHex && (
            <div className="result-display">
              <h4>Envelope (Hex):</h4>
              <code className="envelope-hex">{envelopeHex.slice(0, 100)}...</code>
            </div>
          )}

          {envelopeHex && (
            <div className="button-group">
              <button
                onClick={handleVerifyEnvelope}
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
