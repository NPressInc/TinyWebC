import React, { useState } from 'react';
import './Login.css';
import keyStore from '../utils/keystore';
import sodium from 'libsodium-wrappers';
import { login } from '../utils/api';
import { getDefaultNodeUrl } from '../utils/auth';

function Login({ onLoginSuccess }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [passphrase, setPassphrase] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  
  // Use first node from DEFAULT_NODE_URLS (flat architecture - any node can serve)
  const defaultNodeUrl = getDefaultNodeUrl();

  const handleFileSelect = (event) => {
    const file = event.target.files[0];
    if (file) {
      setSelectedFile(file);
      setError('');
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

  const readFileAsArrayBuffer = (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target.result);
      reader.onerror = (e) => reject(new Error('Failed to read file'));
      reader.readAsArrayBuffer(file);
    });
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    
    if (!selectedFile) {
      setError('Please select a key file');
      return;
    }

    setLoading(true);
    setError('');

    try {
      await sodium.ready;
      await keyStore.init();

      const fileName = selectedFile.name.toLowerCase();
      const isBinary = fileName.endsWith('.bin');

      if (isBinary) {
        // Handle binary .bin files
        const fileBuffer = await readFileAsArrayBuffer(selectedFile);
        const bytes = new Uint8Array(fileBuffer);

        // Check file size to determine format
        if (bytes.length === 120) {
          // Encrypted binary format - requires passphrase
          if (!passphrase.trim()) {
            setError('Please enter the passphrase for this encrypted key file');
            setLoading(false);
            return;
          }

          // Parse binary format: salt (16) + nonce (24) + ciphertext (80)
          const salt = bytes.slice(0, 16);
          const nonce = bytes.slice(16, 40);
          const ciphertext = bytes.slice(40, 120);

          // Convert to hex for storage (matching JSON format)
          const tempKeyData = {
            salt: sodium.to_hex(salt),
            nonce: sodium.to_hex(nonce),
            ciphertext: sodium.to_hex(ciphertext),
            publicKey: null
          };

          localStorage.setItem('tinyweb_import_key', JSON.stringify(tempKeyData));

          // Decrypt and load
          await keyStore.loadKeypair(passphrase);

          // Save to regular storage for future auto-loading
          if (passphrase.trim()) {
            await keyStore.saveKeypair(passphrase);
          } else {
            await keyStore.saveKeypair('');
          }

          // Clean up temp data
          localStorage.removeItem('tinyweb_import_key');
        } else if (bytes.length === 64) {
          // Raw binary format - no passphrase needed
          const keyHex = sodium.to_hex(bytes);
          await keyStore.loadRawKeypair(keyHex, true);
        } else {
          throw new Error(`Invalid binary key file size: ${bytes.length} bytes (expected 64 for raw or 120 for encrypted)`);
        }
      } else {
        // Handle text files (JSON)
        if (!passphrase.trim()) {
          setError('Please enter the passphrase for this key file');
          setLoading(false);
          return;
        }

        const fileContent = await readFileAsText(selectedFile);
        const keyData = JSON.parse(fileContent);

        if (keyData.salt && keyData.nonce && keyData.ciphertext) {
          // Encrypted key file
          const tempKeyData = {
            salt: keyData.salt,
            nonce: keyData.nonce,
            ciphertext: keyData.ciphertext,
            publicKey: keyData.publicKey
          };

          localStorage.setItem('tinyweb_import_key', JSON.stringify(tempKeyData));
          await keyStore.loadKeypair(passphrase);

          if (passphrase.trim()) {
            await keyStore.saveKeypair(passphrase);
          } else {
            await keyStore.saveKeypair('');
          }

          localStorage.removeItem('tinyweb_import_key');
        } else {
          throw new Error('Invalid key file format');
        }
      }

      // Verify key is loaded
      if (!keyStore.isKeypairLoaded()) {
        throw new Error('Failed to load key from file');
      }

      // Send login request to backend
      console.log('[Login] Using node URL:', defaultNodeUrl);
      console.log('[Login] Full login URL:', `${defaultNodeUrl}/auth/login`);
      const loginData = await login(defaultNodeUrl);
      
      // Store login state (node URL is default - any node can serve in flat architecture)
      localStorage.setItem('tinyweb_logged_in', 'true');
      localStorage.setItem('tinyweb_user_pubkey', loginData.pubkey);
      // Note: We store the node URL, but in flat architecture any node can serve requests
      localStorage.setItem('tinyweb_node_url', defaultNodeUrl);

      // Notify parent component
      if (onLoginSuccess) {
        onLoginSuccess(loginData.pubkey, defaultNodeUrl);
      }
    } catch (err) {
      console.error('Login error:', err);
      setError(`Login failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-box">
        <h1>TinyWeb Admin Dashboard</h1>
        <p className="login-subtitle">Please upload your key file to continue</p>

        {error && (
          <div className="login-error">
            {error}
          </div>
        )}

        <form onSubmit={handleLogin} className="login-form">
          <div className="form-group">
            <label>
              Key File:
              <input
                type="file"
                accept=".json,.bin"
                onChange={handleFileSelect}
                disabled={loading}
                required
                className="file-input"
              />
            </label>
            {selectedFile && (
              <div className="file-info">
                Selected: {selectedFile.name}
              </div>
            )}
          </div>

          <div className="form-group">
            <label>
              Passphrase (if encrypted):
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                disabled={loading}
                placeholder="Enter passphrase if key is encrypted"
                className="passphrase-input"
              />
            </label>
            <p className="form-hint">
              Note: Raw .bin files (64 bytes) don't require a passphrase. Encrypted files do.
            </p>
          </div>

          <button 
            type="submit" 
            disabled={loading || !selectedFile}
            className="login-button"
          >
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>

        <div className="login-info">
          <h3>Key File Formats Supported:</h3>
          <ul>
            <li><strong>.json</strong> - Encrypted JSON key file (requires passphrase)</li>
            <li><strong>.bin (64 bytes)</strong> - Raw binary key file (no passphrase)</li>
            <li><strong>.bin (120 bytes)</strong> - Encrypted binary key file (requires passphrase)</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

export default Login;

