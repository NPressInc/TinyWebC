import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { keyStore } from '../utils';
import './KeyManagement.css';

function KeyManagement() {
  const [userKey, setUserKey] = useState('');
  const [newKeyHex, setNewKeyHex] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [isLoaded, setIsLoaded] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);

  useEffect(() => {
    initializeKeyStore();
  }, []);

  const initializeKeyStore = async () => {
    try {
      await keyStore.init();
      if (keyStore.isKeypairLoaded()) {
        setUserKey(keyStore.getPublicKeyHex());
        setIsLoaded(true);
      }
    } catch (err) {
      setError('Failed to initialize keystore: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateKey = async () => {
    try {
      setError('');
      setLoading(true);

      await keyStore.generateKeypair();
      setUserKey(keyStore.getPublicKeyHex());
      setIsLoaded(true);

      console.log('New Ed25519 keypair generated successfully!');
    } catch (err) {
      setError('Failed to generate key: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSaveKey = async () => {
    if (!passphrase.trim()) {
      setError('Please enter a passphrase to encrypt your key');
      return;
    }

    try {
      setError('');
      setLoading(true);

      await keyStore.saveKeypair(passphrase);
      alert('Key saved securely to browser storage!');
    } catch (err) {
      setError('Failed to save key: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLoadKey = async () => {
    if (!passphrase.trim()) {
      setError('Please enter your passphrase');
      return;
    }

    try {
      setError('');
      setLoading(true);

      await keyStore.loadKeypair(passphrase);
      setUserKey(keyStore.getPublicKeyHex());
      setIsLoaded(true);

      console.log('Key loaded successfully!');
    } catch (err) {
      setError('Failed to load key: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleImportKey = async () => {
    if (!newKeyHex.trim()) {
      setError('Please enter a private key in hex format');
      return;
    }

    try {
      setError('');
      setLoading(true);

      await keyStore.loadRawKeypair(newKeyHex.trim());
      setUserKey(keyStore.getPublicKeyHex());
      setIsLoaded(true);
      setNewKeyHex('');

      console.log('Key imported successfully!');
    } catch (err) {
      setError('Failed to import key: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleExportKey = async () => {
    if (!isLoaded) {
      setError('No key loaded to export');
      return;
    }

    try {
      await navigator.clipboard.writeText(userKey);
      alert('Public key copied to clipboard!');
    } catch (err) {
      setError('Failed to copy to clipboard: ' + err.message);
    }
  };

  const handleFileSelect = (event) => {
    const file = event.target.files[0];
    if (file) {
      setSelectedFile(file);
      setError('');
    }
  };

  const handleImportFromFile = async () => {
    if (!selectedFile) {
      setError('Please select a key file first');
      return;
    }

    if (!passphrase.trim()) {
      setError('Please enter the passphrase for this key file');
      return;
    }

    try {
      setError('');
      setLoading(true);

      // Read file content
      const fileContent = await readFileAsText(selectedFile);

      // Try to parse as JSON (encrypted key format)
      try {
        const keyData = JSON.parse(fileContent);

        // Check if it has the expected structure
        if (keyData.salt && keyData.nonce && keyData.ciphertext) {
          // This is an encrypted key file - load it directly
          // Temporarily store the data and load with passphrase
          const tempKeyData = {
            salt: keyData.salt,
            nonce: keyData.nonce,
            ciphertext: keyData.ciphertext,
            publicKey: keyData.publicKey
          };

          localStorage.setItem('tinyweb_import_key', JSON.stringify(tempKeyData));

          // Now load it (this will use the passphrase to decrypt)
          await keyStore.loadKeypair(passphrase);

          // Clean up temp data
          localStorage.removeItem('tinyweb_import_key');

          setUserKey(keyStore.getPublicKeyHex());
          setIsLoaded(true);
          setSelectedFile(null);

          console.log('Key imported from file successfully!');
        } else {
          throw new Error('Invalid key file format');
        }
      } catch (jsonError) {
        // Not JSON, try as raw hex private key
        const trimmedContent = fileContent.trim();
        if (/^[0-9a-fA-F]+$/.test(trimmedContent) && trimmedContent.length === 128) {
          // Looks like a hex private key
          await keyStore.loadRawKeypair(trimmedContent);
          setUserKey(keyStore.getPublicKeyHex());
          setIsLoaded(true);
          setSelectedFile(null);

          console.log('Raw key imported from file successfully!');
        } else {
          throw new Error('File does not contain a valid private key');
        }
      }

    } catch (err) {
      setError('Failed to import key from file: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const readFileAsText = (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target.result);
      reader.onerror = (e) => reject(new Error('Failed to read file'));
      reader.readAsText(file);
    });
  };

  const handleExportToFile = async () => {
    if (!isLoaded) {
      setError('No key loaded to export');
      return;
    }

    if (!passphrase.trim()) {
      setError('Please enter a passphrase to encrypt the exported key');
      return;
    }

    try {
      setError('');

      // Generate encrypted key data
      await keyStore.saveKeypair(passphrase);

      // Get the encrypted data from localStorage
      const keyData = localStorage.getItem('tinyweb_keypair');
      if (!keyData) {
        throw new Error('Failed to generate encrypted key data');
      }

      // Create and download file
      const blob = new Blob([keyData], { type: 'application/json' });
      const url = URL.createObjectURL(blob);

      const link = document.createElement('a');
      link.href = url;
      link.download = `tinyweb-key-${userKey.slice(0, 8)}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      URL.revokeObjectURL(url);

      console.log('Key exported to file successfully!');
    } catch (err) {
      setError('Failed to export key to file: ' + err.message);
    }
  };

  const handleDeleteKey = () => {
    if (window.confirm('Are you sure you want to delete your stored keypair? This cannot be undone!')) {
      keyStore.deleteStoredKeypair();
      keyStore.cleanup();
      setUserKey('');
      setIsLoaded(false);
      console.log('Stored keypair deleted');
    }
  };

  if (loading) {
    return (
      <div className="key-management">
        <div className="key-header">
          <Link to="/" className="back-button">← Back to Messages</Link>
          <h2>Key Management</h2>
        </div>
        <div className="loading">Initializing crypto...</div>
      </div>
    );
  }

  return (
    <div className="key-management">
      <div className="key-header">
        <Link to="/" className="back-button">← Back to Messages</Link>
        <h2>Key Management</h2>
      </div>

      {error && (
        <div className="error-banner">
          <span className="error-icon">⚠️</span>
          {error}
        </div>
      )}

      <div className="key-content">
        <div className="current-key-section">
          <h3>Current User Key</h3>
          {isLoaded ? (
            <div className="key-display">
              <code className="key-value">{userKey}</code>
              <button onClick={handleExportKey} className="copy-button">
                📋 Copy
              </button>
            </div>
          ) : (
            <div className="no-key-message">
              <p>No key loaded. Generate a new key or load an existing one.</p>
            </div>
          )}
          <p className="key-info">
            This is your Ed25519 public key (for signing/identity). It gets converted to X25519 for encryption.
          </p>
        </div>

        <div className="key-actions">
          <div className="action-section">
            <h3>Generate New Key</h3>
            <p>Create a new Ed25519 key pair for signing and encryption.</p>
            <button onClick={handleGenerateKey} className="action-button primary" disabled={loading}>
              {loading ? 'Generating...' : 'Generate New Key'}
            </button>
          </div>

          <div className="action-section">
            <h3>Import Raw Key</h3>
            <p>Import an existing Ed25519 private key (hex format).</p>
            <div className="import-form">
              <input
                type="text"
                value={newKeyHex}
                onChange={(e) => setNewKeyHex(e.target.value)}
                placeholder="Enter private key (128-character hex)"
                className="key-input"
                maxLength={128}
              />
              <button
                onClick={handleImportKey}
                disabled={!newKeyHex.trim() || loading}
                className="action-button secondary"
              >
                Import
              </button>
            </div>
          </div>

          <div className="action-section">
            <h3>Import from File</h3>
            <p>Import an encrypted key file (.json) or raw key file (.txt).</p>
            <div className="import-form">
              <input
                type="file"
                accept=".json,.txt"
                onChange={handleFileSelect}
                className="file-input"
              />
              {selectedFile && (
                <div className="file-info">
                  Selected: {selectedFile.name}
                </div>
              )}
              <button
                onClick={handleImportFromFile}
                disabled={!selectedFile || !passphrase.trim() || loading}
                className="action-button secondary"
              >
                Import from File
              </button>
            </div>
          </div>
        </div>

        {isLoaded && (
          <div className="key-actions">
            <div className="action-section">
              <h3>Save Key Securely</h3>
              <p>Encrypt and save your key to browser storage.</p>
              <div className="import-form">
                <input
                  type="password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  placeholder="Enter encryption passphrase"
                  className="key-input"
                />
                <button
                  onClick={handleSaveKey}
                  disabled={!passphrase.trim() || loading}
                  className="action-button primary"
                >
                  Save Key
                </button>
              </div>
            </div>

            <div className="action-section">
              <h3>Load Saved Key</h3>
              <p>Load your previously saved key from browser storage.</p>
              <div className="import-form">
                <input
                  type="password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  placeholder="Enter your passphrase"
                  className="key-input"
                />
                <button
                  onClick={handleLoadKey}
                  disabled={!passphrase.trim() || loading}
                  className="action-button secondary"
                >
                  Load Key
                </button>
              </div>
            </div>

            <div className="action-section">
              <h3>Export to File</h3>
              <p>Download your key as an encrypted file for backup.</p>
              <div className="import-form">
                <input
                  type="password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  placeholder="Enter encryption passphrase"
                  className="key-input"
                />
                <button
                  onClick={handleExportToFile}
                  disabled={!passphrase.trim() || loading}
                  className="action-button primary"
                >
                  Export to File
                </button>
              </div>
            </div>
          </div>
        )}

        {isLoaded && (
          <div className="danger-zone">
            <div className="action-section danger">
              <h3>⚠️ Danger Zone</h3>
              <p>These actions cannot be undone.</p>
              <button onClick={handleDeleteKey} className="action-button danger">
                Delete Stored Key
              </button>
            </div>
          </div>
        )}

        <div className="key-education">
          <h3>How Keys Work</h3>
          <div className="education-content">
            <div className="education-item">
              <h4>🔐 Ed25519 → X25519 Conversion</h4>
              <p>Your Ed25519 keypair gets converted to X25519 for encryption. Same keys, different algorithms!</p>
            </div>

            <div className="education-item">
              <h4>✍️ Digital Signatures</h4>
              <p>Messages are signed with Ed25519, proving authenticity and preventing tampering.</p>
            </div>

            <div className="education-item">
              <h4>🔒 Hybrid Encryption</h4>
              <p>AES-256-GCM encrypts message content, X25519 handles key exchange. Perfect forward secrecy!</p>
            </div>

            <div className="education-item">
              <h4>🔑 Secure Storage</h4>
              <p>Keys are encrypted with your passphrase before local storage. Never stored in plain text.</p>
            </div>
          </div>
        </div>

        <div className="security-notice">
          <div className="notice-header">
            <span className="notice-icon">🔒</span>
            <h3>Security Status</h3>
          </div>
          <p>
            ✅ Using libsodium.js - audited cryptographic library<br/>
            ✅ Keys never leave your browser<br/>
            ✅ All encryption happens client-side<br/>
            ✅ Forward secrecy with ephemeral keys
          </p>
        </div>
      </div>
    </div>
  );
}

export default KeyManagement;
