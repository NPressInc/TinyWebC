import sodium from 'libsodium-wrappers';

/**
 * Frontend keystore utility - mirrors backend keystore logic
 * Manages Ed25519 keys for signing and converts to X25519 for encryption
 */

// Key sizes (matching backend) - these are all 32 bytes
const SIGN_PUBKEY_SIZE = 32;    // crypto_sign_PUBLICKEYBYTES
const SIGN_SECRET_SIZE = 64;    // crypto_sign_SECRETKEYBYTES
const PUBKEY_SIZE = 32;         // crypto_box_PUBLICKEYBYTES
const SECRET_SIZE = 32;         // crypto_box_SECRETKEYBYTES

class KeyStore {
  constructor() {
    this.initialized = false;
    this.signPublicKey = null;
    this.signSecretKey = null;
  }

  /**
   * Initialize libsodium and the keystore
   * Also attempts to auto-load keys from localStorage if available
   */
  async init() {
    if (this.initialized) {
      // If already initialized but keys aren't loaded, try to auto-load
      if (!this.isKeypairLoaded()) {
        await this._tryAutoLoad();
      }
      return true;
    }

    await sodium.ready;
    this.initialized = true;
    console.log('Frontend keystore initialized');
    
    // Try to auto-load keys from localStorage
    await this._tryAutoLoad();
    
    return true;
  }

  /**
   * Try to auto-load keys from localStorage (with empty passphrase)
   * This only works if keys were saved with empty passphrase
   */
  async _tryAutoLoad() {
    try {
      const stored = localStorage.getItem('tinyweb_keypair');
      if (stored && !this.isKeypairLoaded()) {
        console.log('Attempting to auto-load keypair from localStorage...');
        // Try to load with empty passphrase
        await this.loadKeypair('');
        console.log('Auto-loaded keypair from localStorage successfully');
      } else if (!stored) {
        console.log('No keypair found in localStorage');
      } else {
        console.log('Keypair already loaded in memory');
      }
    } catch (err) {
      // If auto-load fails, keys are encrypted - user needs to enter passphrase
      console.log('Auto-load failed (keys may be encrypted with passphrase):', err.message);
    }
  }

  /**
   * Generate a new Ed25519 keypair
   */
  async generateKeypair() {
    if (!this.initialized) await this.init();

    const keypair = sodium.crypto_sign_keypair();
    this.signPublicKey = keypair.publicKey;
    this.signSecretKey = keypair.privateKey;

    console.log('Generated new Ed25519 keypair');
    return true;
  }

  /**
   * Save the keypair to localStorage (encrypted)
   */
  async saveKeypair(passphrase) {
    if (!this.signSecretKey) {
      throw new Error('No keypair loaded');
    }

    // Ensure sodium is ready
    if (!this.initialized) {
      await this.init();
    }
    await sodium.ready;

    // If passphrase is empty, use empty string (less secure but convenient for auto-loading)
    const actualPassphrase = passphrase || '';
    
    try {
      // Derive encryption key from passphrase
      // Use constants with proper null/undefined checks (libsodium-wrappers provides these after sodium.ready)
      // If they're still undefined, use standard libsodium values
      const SALTBYTES = (sodium.crypto_pwhash_SALTBYTES !== undefined && sodium.crypto_pwhash_SALTBYTES !== null) 
        ? sodium.crypto_pwhash_SALTBYTES 
        : 16;
      const KEYBYTES = (sodium.crypto_secretbox_KEYBYTES !== undefined && sodium.crypto_secretbox_KEYBYTES !== null)
        ? sodium.crypto_secretbox_KEYBYTES
        : 32;
      const NONCEBYTES = (sodium.crypto_secretbox_NONCEBYTES !== undefined && sodium.crypto_secretbox_NONCEBYTES !== null)
        ? sodium.crypto_secretbox_NONCEBYTES
        : 24;
      
      if (!SALTBYTES || !KEYBYTES || !NONCEBYTES) {
        throw new Error(`Invalid sodium constants: SALTBYTES=${SALTBYTES}, KEYBYTES=${KEYBYTES}, NONCEBYTES=${NONCEBYTES}`);
      }
      
      const salt = sodium.randombytes_buf(SALTBYTES);
      
      // Derive key from passphrase using crypto_generichash (simpler than crypto_pwhash)
      // This is less secure than Argon2 but works in browser environment
      const keyMaterial = new Uint8Array(salt.length + actualPassphrase.length);
      keyMaterial.set(salt, 0);
      keyMaterial.set(new TextEncoder().encode(actualPassphrase), salt.length);
      const key = sodium.crypto_generichash(KEYBYTES, keyMaterial);

      // Generate nonce and encrypt
      const nonce = sodium.randombytes_buf(NONCEBYTES);
      const ciphertext = sodium.crypto_secretbox_easy(this.signSecretKey, nonce, key);

      // Store in localStorage
      const keyData = {
        salt: sodium.to_hex(salt),
        nonce: sodium.to_hex(nonce),
        ciphertext: sodium.to_hex(ciphertext),
        publicKey: sodium.to_hex(this.signPublicKey)
      };

      const jsonData = JSON.stringify(keyData);
      localStorage.setItem('tinyweb_keypair', jsonData);
      
      // Verify it was saved
      const saved = localStorage.getItem('tinyweb_keypair');
      if (!saved || saved !== jsonData) {
        throw new Error('Failed to verify keypair was saved to localStorage');
      }
      
      console.log('Keypair saved to localStorage successfully');
      return true;
    } catch (err) {
      console.error('Error saving keypair to localStorage:', err);
      throw new Error(`Failed to save keypair: ${err.message}`);
    }
  }

  /**
   * Load keypair from localStorage (decrypt with passphrase)
   */
  async loadKeypair(passphrase) {
    // Check both regular storage and import storage
    let stored = localStorage.getItem('tinyweb_keypair');
    if (!stored) {
      stored = localStorage.getItem('tinyweb_import_key');
    }
    if (!stored) {
      throw new Error('No keypair found in storage');
    }

    const keyData = JSON.parse(stored);

    // Convert from hex
    const salt = sodium.from_hex(keyData.salt);
    const nonce = sodium.from_hex(keyData.nonce);
    const ciphertext = sodium.from_hex(keyData.ciphertext);

    // Use empty string if passphrase is not provided
    const actualPassphrase = passphrase || '';
    
    // Use constants with fallbacks
    const KEYBYTES = sodium.crypto_secretbox_KEYBYTES || 32;
    
    // Derive decryption key from passphrase using crypto_generichash (same as encryption)
    const keyMaterial = new Uint8Array(salt.length + actualPassphrase.length);
    keyMaterial.set(salt, 0);
    keyMaterial.set(new TextEncoder().encode(actualPassphrase), salt.length);
    const key = sodium.crypto_generichash(KEYBYTES, keyMaterial);

    // Decrypt
    try {
      this.signSecretKey = sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
      // Derive public key from secret key (or use stored one if available)
      if (keyData.publicKey) {
        this.signPublicKey = sodium.from_hex(keyData.publicKey);
      } else {
        // Derive public key from secret key
        // Note: crypto_sign_ed25519_sk_to_pk doesn't exist in libsodium-wrappers
        // In Ed25519, the 64-byte secret key contains the public key in the last 32 bytes
        if (typeof sodium.crypto_sign_ed25519_sk_to_pk === 'function') {
          this.signPublicKey = sodium.crypto_sign_ed25519_sk_to_pk(this.signSecretKey);
        } else if (this.signSecretKey.length === 64) {
          // Extract public key from last 32 bytes of secret key (Ed25519 format)
          this.signPublicKey = this.signSecretKey.slice(32, 64);
        } else {
          // Fallback: extract public key from secret key
          this.signPublicKey = this.signSecretKey.slice(32, 64);
        }
      }
      console.log('Keypair loaded from localStorage');
      return true;
    } catch (error) {
      throw new Error('Failed to decrypt keypair - wrong passphrase?');
    }
  }

  /**
   * Load raw Ed25519 keypair directly (for testing)
   * Optionally saves to localStorage for persistence
   */
  async loadRawKeypair(privateKeyHex, saveToStorage = true) {
    if (!this.initialized) await this.init();

    this.signSecretKey = sodium.from_hex(privateKeyHex);
    
    // Derive public key from secret key
    // Note: crypto_sign_ed25519_sk_to_pk doesn't exist in libsodium-wrappers
    // In Ed25519, the 64-byte secret key contains the public key in the last 32 bytes
    if (typeof sodium.crypto_sign_ed25519_sk_to_pk === 'function') {
      this.signPublicKey = sodium.crypto_sign_ed25519_sk_to_pk(this.signSecretKey);
    } else if (this.signSecretKey.length === 64) {
      // Extract public key from last 32 bytes of secret key (Ed25519 format)
      this.signPublicKey = this.signSecretKey.slice(32, 64);
    } else {
      // Fallback: extract public key from secret key
      this.signPublicKey = this.signSecretKey.slice(32, 64);
    }

    // Auto-save to localStorage (unencrypted for convenience, or with empty passphrase)
    if (saveToStorage) {
      try {
        // Ensure sodium is ready before saving
        await sodium.ready;
        // Save with empty passphrase for auto-loading (user can change this later)
        await this.saveKeypair('');
        console.log('Keypair auto-saved to localStorage');
        
        // Verify it was actually saved
        const saved = localStorage.getItem('tinyweb_keypair');
        if (!saved) {
          console.error('Failed to verify keypair was saved to localStorage');
        } else {
          console.log('Keypair verified in localStorage');
        }
      } catch (err) {
        console.error('Failed to auto-save keypair:', err);
        console.error('Error details:', err.message, err.stack);
        // Don't fail - key is still loaded in memory
      }
    }

    console.log('Raw keypair loaded');
    return true;
  }

  /**
   * Get the Ed25519 public key (for signing/identity)
   */
  getPublicKey() {
    if (!this.signPublicKey) {
      throw new Error('No keypair loaded');
    }
    return this.signPublicKey;
  }

  /**
   * Get the Ed25519 public key as hex string
   */
  getPublicKeyHex() {
    return sodium.to_hex(this.getPublicKey());
  }

  /**
   * Get the X25519 public key (converted from Ed25519, for encryption)
   */
  getEncryptionPublicKey() {
    if (!this.signPublicKey) {
      throw new Error('No keypair loaded');
    }

    // Convert Ed25519 public key to X25519
    return sodium.crypto_sign_ed25519_pk_to_curve25519(this.signPublicKey);
  }

  /**
   * Get the X25519 public key as hex string
   */
  getEncryptionPublicKeyHex() {
    return sodium.to_hex(this.getEncryptionPublicKey());
  }

  /**
   * Get the Ed25519 private key (internal use only)
   */
  _getPrivateKey() {
    if (!this.signSecretKey) {
      throw new Error('No keypair loaded');
    }
    return this.signSecretKey;
  }

  /**
   * Get the X25519 private key (converted from Ed25519, for encryption)
   */
  _getEncryptionPrivateKey() {
    if (!this.signSecretKey) {
      throw new Error('No keypair loaded');
    }

    // Convert Ed25519 private key to X25519
    return sodium.crypto_sign_ed25519_sk_to_curve25519(this.signSecretKey);
  }

  /**
   * Check if a keypair is currently loaded
   */
  isKeypairLoaded() {
    return this.signPublicKey !== null && this.signSecretKey !== null;
  }

  /**
   * Clear the keystore
   * Matches C implementation: keystore.c::keystore_cleanup
   */
  cleanup() {
    if (this.signPublicKey) {
      sodium.memzero(this.signPublicKey);
    }
    if (this.signSecretKey) {
      sodium.memzero(this.signSecretKey);
    }
    this.signPublicKey = null;
    this.signSecretKey = null;
  }

  /**
   * Delete stored keypair from localStorage
   */
  deleteStoredKeypair() {
    localStorage.removeItem('tinyweb_keypair');
    console.log('Stored keypair deleted');
  }

  // Demo/testing helper methods (not for production use)
  async _generateKeypairForDemo() {
    if (!this.initialized) await this.init();
    const keypair = sodium.crypto_sign_keypair();
    
    // Also convert Ed25519 keys to X25519 for encryption
    const encryptionPublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(keypair.publicKey);
    const encryptionPrivateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(keypair.privateKey);
    
    return {
      publicKey: keypair.publicKey,
      privateKey: keypair.privateKey,
      encryptionPublicKey,
      encryptionPrivateKey
    };
  }

  async _keyToHex(key) {
    if (!this.initialized) await this.init();
    return sodium.to_hex(key);
  }

  async _hexToKey(hexString) {
    if (!this.initialized) await this.init();
    return sodium.from_hex(hexString);
  }

  async _payloadToHex(payload) {
    if (!this.initialized) await this.init();
    // Use proper serialization from encryption.js
    const { serializeEncryptedPayload } = await import('./encryption.js');
    return sodium.to_hex(serializeEncryptedPayload(payload));
  }

  async _hexToPayload(hexString) {
    if (!this.initialized) await this.init();
    // Use proper deserialization from encryption.js
    const { deserializeEncryptedPayload } = await import('./encryption.js');
    const bytes = sodium.from_hex(hexString);
    return deserializeEncryptedPayload(bytes);
  }

}

// Export a singleton instance
const keyStore = new KeyStore();
export default keyStore;

// Export constants for external use
export { SIGN_PUBKEY_SIZE, SIGN_SECRET_SIZE, PUBKEY_SIZE, SECRET_SIZE };
