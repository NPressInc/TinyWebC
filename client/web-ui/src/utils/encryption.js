import sodium from 'libsodium-wrappers';
import keyStore from './keystore.js';

/**
 * Frontend encryption utility - mirrors backend encryption logic
 * Implements multi-recipient hybrid encryption with forward secrecy
 */

// Constants matching backend
const NONCE_SIZE = sodium.crypto_box_NONCEBYTES;         // 24
const MAC_SIZE = sodium.crypto_box_MACBYTES;             // 16
const MAX_PLAINTEXT_SIZE = 2048;                         // 2KB max
const MAX_RECIPIENTS = 50;                               // Max recipients per message

/**
 * Encrypted payload structure matching backend
 */
class EncryptedPayload {
  constructor() {
    this.ciphertext = null;           // Encrypted message (AES-GCM)
    this.nonce = null;                // Nonce for symmetric encryption (24 bytes)
    this.encryptedKeys = null;        // Encrypted symmetric keys (one per recipient)
    this.keyNonces = null;            // Nonces for encrypted keys
    this.ephemeralPubkey = null;      // Ephemeral public key (32 bytes)
    this.numRecipients = 0;
  }
}

/**
 * Encrypt a message for multiple recipients using hybrid encryption
 * @param {Uint8Array} plaintext - The message to encrypt
 * @param {Uint8Array[]} recipientPubkeys - Array of recipient X25519 public keys
 * @returns {EncryptedPayload} - The encrypted payload
 */
export async function encryptPayloadMulti(plaintext, recipientPubkeys) {
  if (!plaintext || plaintext.length === 0) {
    throw new Error('Plaintext cannot be empty');
  }

  if (plaintext.length > MAX_PLAINTEXT_SIZE) {
    throw new Error(`Plaintext too large: ${plaintext.length} > ${MAX_PLAINTEXT_SIZE}`);
  }

  if (!recipientPubkeys || recipientPubkeys.length === 0) {
    throw new Error('Must specify at least one recipient');
  }

  if (recipientPubkeys.length > MAX_RECIPIENTS) {
    throw new Error(`Too many recipients: ${recipientPubkeys.length} > ${MAX_RECIPIENTS}`);
  }

  // Generate ephemeral keypair for this message (forward secrecy)
  const ephemeralKeypair = sodium.crypto_box_keypair();
  const ephemeralSecretKey = ephemeralKeypair.privateKey;
  const ephemeralPubkey = ephemeralKeypair.publicKey;

  // Generate symmetric key and nonce for AES-GCM
  const symmetricKey = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
  const messageNonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);

  // Encrypt the message with AES-GCM
  const ciphertext = sodium.crypto_secretbox_easy(plaintext, messageNonce, symmetricKey);

  // Encrypt the symmetric key for each recipient
  const encryptedKeys = [];
  const keyNonces = [];

  for (const recipientPubkey of recipientPubkeys) {
    // Generate unique nonce for this recipient
    const keyNonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);

    // Encrypt symmetric key using recipient's public key and our ephemeral private key
    const encryptedKey = sodium.crypto_box_easy(symmetricKey, keyNonce, recipientPubkey, ephemeralSecretKey);

    encryptedKeys.push(encryptedKey);
    keyNonces.push(keyNonce);
  }

  // Create the encrypted payload
  const payload = new EncryptedPayload();
  payload.ciphertext = ciphertext;
  payload.nonce = messageNonce;
  payload.encryptedKeys = encryptedKeys;
  payload.keyNonces = keyNonces;
  payload.ephemeralPubkey = ephemeralPubkey;
  payload.numRecipients = recipientPubkeys.length;

  // Clean up sensitive data
  sodium.memzero(symmetricKey);
  sodium.memzero(ephemeralSecretKey);

  return payload;
}

/**
 * Decrypt a message using the recipient's private key
 * @param {EncryptedPayload} encrypted - The encrypted payload
 * @param {Uint8Array} recipientPubkey - The recipient's X25519 public key (for key lookup)
 * @returns {Uint8Array} - The decrypted plaintext
 */
export async function decryptPayload(encrypted, recipientPubkey) {
  if (!encrypted || !recipientPubkey) {
    throw new Error('Invalid parameters');
  }

  // Find our encrypted key (we need to know which recipient we are)
  // In practice, this would be determined by checking which key we can decrypt
  let symmetricKey = null;
  let found = false;

  for (let i = 0; i < encrypted.numRecipients; i++) {
    try {
      // Try to decrypt this key using our private key
      const ourPrivateKey = keyStore._getEncryptionPrivateKey();

      symmetricKey = sodium.crypto_box_open_easy(
        encrypted.encryptedKeys[i],
        encrypted.keyNonces[i],
        encrypted.ephemeralPubkey,
        ourPrivateKey
      );

      found = true;
      break;
    } catch (error) {
      // This key wasn't for us, try the next one
      continue;
    }
  }

  if (!found || !symmetricKey) {
    throw new Error('Could not decrypt - message not intended for this recipient');
  }

  // Decrypt the message
  try {
    const plaintext = sodium.crypto_secretbox_open_easy(
      encrypted.ciphertext,
      encrypted.nonce,
      symmetricKey
    );

    // Clean up
    sodium.memzero(symmetricKey);

    return plaintext;
  } catch (error) {
    sodium.memzero(symmetricKey);
    throw new Error('Failed to decrypt message');
  }
}

/**
 * Serialize an encrypted payload to bytes (for storage/transmission)
 * @param {EncryptedPayload} payload - The payload to serialize
 * @returns {Uint8Array} - Serialized bytes
 */
export function serializeEncryptedPayload(payload) {
  // Calculate total size
  const totalSize =
    4 + // numRecipients (uint32)
    NONCE_SIZE + // message nonce
    4 + payload.ciphertext.length + // ciphertext length + data
    4 + payload.ephemeralPubkey.length + // ephemeral pubkey length + data
    4 + // num keys
    payload.encryptedKeys.length * (4 + NONCE_SIZE) + // key nonces
    payload.encryptedKeys.reduce((sum, key) => sum + 4 + key.length, 0); // encrypted keys

  const buffer = new Uint8Array(totalSize);
  let offset = 0;

  // Write numRecipients
  new DataView(buffer.buffer).setUint32(offset, payload.numRecipients, true);
  offset += 4;

  // Write message nonce
  buffer.set(payload.nonce, offset);
  offset += NONCE_SIZE;

  // Write ciphertext
  new DataView(buffer.buffer).setUint32(offset, payload.ciphertext.length, true);
  offset += 4;
  buffer.set(payload.ciphertext, offset);
  offset += payload.ciphertext.length;

  // Write ephemeral pubkey
  new DataView(buffer.buffer).setUint32(offset, payload.ephemeralPubkey.length, true);
  offset += 4;
  buffer.set(payload.ephemeralPubkey, offset);
  offset += payload.ephemeralPubkey.length;

  // Write encrypted keys count
  new DataView(buffer.buffer).setUint32(offset, payload.encryptedKeys.length, true);
  offset += 4;

  // Write key nonces and encrypted keys
  for (let i = 0; i < payload.encryptedKeys.length; i++) {
    buffer.set(payload.keyNonces[i], offset);
    offset += NONCE_SIZE;

    const key = payload.encryptedKeys[i];
    new DataView(buffer.buffer).setUint32(offset, key.length, true);
    offset += 4;
    buffer.set(key, offset);
    offset += key.length;
  }

  return buffer;
}

/**
 * Deserialize bytes to an encrypted payload
 * @param {Uint8Array} bytes - The serialized payload
 * @returns {EncryptedPayload} - The deserialized payload
 */
export function deserializeEncryptedPayload(bytes) {
  const buffer = new Uint8Array(bytes);
  let offset = 0;

  // Read numRecipients
  const numRecipients = new DataView(buffer.buffer).getUint32(offset, true);
  offset += 4;

  // Read message nonce
  const nonce = buffer.slice(offset, offset + NONCE_SIZE);
  offset += NONCE_SIZE;

  // Read ciphertext
  const ciphertextLen = new DataView(buffer.buffer).getUint32(offset, true);
  offset += 4;
  const ciphertext = buffer.slice(offset, offset + ciphertextLen);
  offset += ciphertextLen;

  // Read ephemeral pubkey
  const ephemeralLen = new DataView(buffer.buffer).getUint32(offset, true);
  offset += 4;
  const ephemeralPubkey = buffer.slice(offset, offset + ephemeralLen);
  offset += ephemeralLen;

  // Read encrypted keys count
  const numKeys = new DataView(buffer.buffer).getUint32(offset, true);
  offset += 4;

  // Read key nonces and encrypted keys
  const encryptedKeys = [];
  const keyNonces = [];

  for (let i = 0; i < numKeys; i++) {
    const keyNonce = buffer.slice(offset, offset + NONCE_SIZE);
    offset += NONCE_SIZE;

    const keyLen = new DataView(buffer.buffer).getUint32(offset, true);
    offset += 4;
    const encryptedKey = buffer.slice(offset, offset + keyLen);
    offset += keyLen;

    keyNonces.push(keyNonce);
    encryptedKeys.push(encryptedKey);
  }

  const payload = new EncryptedPayload();
  payload.ciphertext = ciphertext;
  payload.nonce = nonce;
  payload.encryptedKeys = encryptedKeys;
  payload.keyNonces = keyNonces;
  payload.ephemeralPubkey = ephemeralPubkey;
  payload.numRecipients = numRecipients;

  return payload;
}

/**
 * Convert encrypted payload to hex string for transmission
 * @param {EncryptedPayload} payload - The payload
 * @returns {string} - Hex-encoded payload
 */
export function encryptedPayloadToHex(payload) {
  const bytes = serializeEncryptedPayload(payload);
  return sodium.to_hex(bytes);
}

/**
 * Convert hex string to encrypted payload
 * @param {string} hexString - Hex-encoded payload
 * @returns {EncryptedPayload} - The payload
 */
export function encryptedPayloadFromHex(hexString) {
  const bytes = sodium.from_hex(hexString);
  return deserializeEncryptedPayload(bytes);
}

export { EncryptedPayload, MAX_PLAINTEXT_SIZE, MAX_RECIPIENTS };
