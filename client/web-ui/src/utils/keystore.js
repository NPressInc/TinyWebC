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
   */
  async init() {
    if (this.initialized) return true;

    await sodium.ready;
    this.initialized = true;
    console.log('Frontend keystore initialized');
    return true;
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

    // Derive encryption key from passphrase
    const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    const key = sodium.crypto_pwhash(
      sodium.crypto_secretbox_KEYBYTES,
      passphrase,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_DEFAULT
    );

    // Generate nonce and encrypt
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const ciphertext = sodium.crypto_secretbox_easy(this.signSecretKey, nonce, key);

    // Store in localStorage
    const keyData = {
      salt: sodium.to_hex(salt),
      nonce: sodium.to_hex(nonce),
      ciphertext: sodium.to_hex(ciphertext),
      publicKey: sodium.to_hex(this.signPublicKey)
    };

    localStorage.setItem('tinyweb_keypair', JSON.stringify(keyData));
    console.log('Keypair saved to localStorage');
    return true;
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

    // Derive decryption key from passphrase
    const key = sodium.crypto_pwhash(
      sodium.crypto_secretbox_KEYBYTES,
      passphrase,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_DEFAULT
    );

    // Decrypt
    try {
      this.signSecretKey = sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
      this.signPublicKey = sodium.from_hex(keyData.publicKey);
      console.log('Keypair loaded from localStorage');
      return true;
    } catch (error) {
      throw new Error('Failed to decrypt keypair - wrong passphrase?');
    }
  }

  /**
   * Load raw Ed25519 keypair directly (for testing)
   */
  async loadRawKeypair(privateKeyHex) {
    if (!this.initialized) await this.init();

    this.signSecretKey = sodium.from_hex(privateKeyHex);
    this.signPublicKey = sodium.crypto_sign_ed25519_sk_to_pk(this.signSecretKey);

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

  async _envelopeToHex(envelope) {
    if (!this.initialized) await this.init();
    // Use proper serialization from encryption.js
    const { serializeEncryptedPayload } = await import('./encryption.js');
    const envelopeData = {
      header: {
        ...envelope.header,
        senderPubkey: Array.from(envelope.header.senderPubkey), // Convert Uint8Array to regular array
        recipientPubkeys: envelope.header.recipientPubkeys.map(pk => Array.from(pk))
      },
      encryptedPayloadHex: sodium.to_hex(serializeEncryptedPayload(envelope.encryptedPayload)),
      signatureHex: sodium.to_hex(envelope.signature)
    };
    return btoa(JSON.stringify(envelopeData));
  }

  async _hexToEnvelope(envelopeHex) {
    if (!this.initialized) await this.init();
    // Use proper deserialization from encryption.js
    const { deserializeEncryptedPayload } = await import('./encryption.js');
    const envelopeData = JSON.parse(atob(envelopeHex));

    // Convert header fields back to Uint8Arrays
    const header = {
      ...envelopeData.header,
      senderPubkey: new Uint8Array(envelopeData.header.senderPubkey),
      recipientPubkeys: envelopeData.header.recipientPubkeys.map(pk => new Uint8Array(pk))
    };

    return {
      header: header,
      encryptedPayload: deserializeEncryptedPayload(sodium.from_hex(envelopeData.encryptedPayloadHex)),
      signature: sodium.from_hex(envelopeData.signatureHex)
    };
  }
}

// Export a singleton instance
const keyStore = new KeyStore();
export default keyStore;

// Export constants for external use
export { SIGN_PUBKEY_SIZE, SIGN_SECRET_SIZE, PUBKEY_SIZE, SECRET_SIZE };
