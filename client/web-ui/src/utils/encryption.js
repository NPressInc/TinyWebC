import sodium from 'libsodium-wrappers';
import keyStore from './keystore.js';
import { htonll, ntohll } from './byteorder.js';

/**
 * Frontend encryption utility - mirrors backend encryption logic
 * Implements multi-recipient hybrid encryption with forward secrecy
 */

// Constants matching backend C implementation (encryption.h)
// Use sodium constants directly instead of mutable variables
const PUBKEY_SIZE = 32;      // crypto_box_PUBLICKEYBYTES
const MAX_PLAINTEXT_SIZE = 2048;                         // 2KB max
const MAX_RECIPIENTS = 50;                               // Max recipients per message
const ENCRYPTED_KEY_SIZE = 48;                           // crypto_secretbox_KEYBYTES (32) + MAC_SIZE (16)

// Ensure sodium is ready
async function ensureSodiumReady() {
  await sodium.ready;
}

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
  await ensureSodiumReady();
  
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
    // Matches C backend: crypto_box_easy(ciphertext, plaintext, nonce, recipient_pubkey, sender_privkey)
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
 * Matches C implementation: encryption.c::decrypt_payload
 * Takes recipient pubkeys array and finds matching index
 *
 * @param {EncryptedPayload} encrypted - The encrypted payload
 * @param {Uint8Array[]} recipientPubkeys - Array of recipient X25519 public keys
 * @param {Uint8Array} [recipientPrivkey] - Optional: The recipient's X25519 private key (for demo purposes)
 * @param {Uint8Array} [recipientPubkey] - Optional: The recipient's X25519 public key (for demo purposes)
 * @returns {Uint8Array} - The decrypted plaintext
 */
export async function decryptPayload(encrypted, recipientPubkeys, recipientPrivkey = null, recipientPubkey = null) {
  await ensureSodiumReady();
  
  if (!encrypted || !recipientPubkeys || recipientPubkeys.length === 0) {
    throw new Error('Invalid parameters');
  }

  // Check ciphertext size (matching C implementation)
  const MAX_CIPHERTEXT_SIZE = MAX_PLAINTEXT_SIZE + 16; // MAX + MAC
  if (encrypted.ciphertext.length > MAX_CIPHERTEXT_SIZE) {
    throw new Error(`Ciphertext size exceeds maximum allowed size`);
  }

  // Get our public key and private key (from parameters or keystore)
  let ourPublicKey;
  let ourPrivateKey;

  if (recipientPubkey && recipientPrivkey) {
    // Both provided - use them directly (demo mode with explicit keys)
    ourPublicKey = recipientPubkey;
    ourPrivateKey = recipientPrivkey;
  } else {
    // Use keystore (normal mode)
    ourPublicKey = keyStore.getEncryptionPublicKey();
    ourPrivateKey = recipientPrivkey || keyStore._getEncryptionPrivateKey();
  }

  // Find the index of our public key in the recipient pubkeys array
  // This matches the C backend logic
  let recipientIndex = -1;
  for (let i = 0; i < recipientPubkeys.length; i++) {
    if (sodium.memcmp(ourPublicKey, recipientPubkeys[i])) {
      recipientIndex = i;
      break;
    }
  }

  if (recipientIndex === -1) {
    throw new Error('Recipient public key not found in the list');
  }

  // Decrypt the symmetric key using our private key at the matched index
  let symmetricKey;
  try {
    symmetricKey = sodium.crypto_box_open_easy(
      encrypted.encryptedKeys[recipientIndex],
      encrypted.keyNonces[recipientIndex],
      encrypted.ephemeralPubkey,
      ourPrivateKey
    );
  } catch (error) {
    throw new Error('Failed to decrypt symmetric key');
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
 * Matches C implementation: encryption.c::encrypted_payload_serialize
 * @param {EncryptedPayload} payload - The payload to serialize
 * @returns {Uint8Array} - Serialized bytes
 */
export function serializeEncryptedPayload(payload) {
  // Calculate total size (matching C implementation)
  const totalSize =
    8 + // num_recipients (size_t = 8 bytes)
    8 + // ciphertext_len (size_t = 8 bytes)
    PUBKEY_SIZE + // ephemeral_pubkey (32 bytes)
    sodium.crypto_secretbox_NONCEBYTES + // nonce (24 bytes)
    payload.ciphertext.length + // ciphertext
    payload.numRecipients * ENCRYPTED_KEY_SIZE + // encrypted_keys (48 bytes each)
    payload.numRecipients * sodium.crypto_box_NONCEBYTES; // key_nonces (24 bytes each)

  const buffer = new Uint8Array(totalSize);
  const view = new DataView(buffer.buffer);
  let offset = 0;

  // Write num_recipients (8 bytes, network byte order to match C backend)
  // eslint-disable-next-line no-undef
  view.setBigUint64(offset, htonll(BigInt(payload.numRecipients)), false);
  offset += 8;

  // Write ciphertext_len (8 bytes, network byte order)
  // eslint-disable-next-line no-undef
  view.setBigUint64(offset, htonll(BigInt(payload.ciphertext.length)), false);
  offset += 8;

  // Write ephemeral_pubkey (PUBKEY_SIZE bytes)
  buffer.set(payload.ephemeralPubkey, offset);
  offset += PUBKEY_SIZE;

  // Write nonce (24 bytes)
  buffer.set(payload.nonce, offset);
  offset += sodium.crypto_secretbox_NONCEBYTES;

  // Write ciphertext
  buffer.set(payload.ciphertext, offset);
  offset += payload.ciphertext.length;

  // Write encrypted_keys (all keys concatenated, 48 bytes each)
  for (let i = 0; i < payload.encryptedKeys.length; i++) {
    buffer.set(payload.encryptedKeys[i], offset);
    offset += payload.encryptedKeys[i].length;
  }

  // Write key_nonces (all nonces concatenated, 24 bytes each)
  for (let i = 0; i < payload.keyNonces.length; i++) {
    buffer.set(payload.keyNonces[i], offset);
    offset += payload.keyNonces[i].length;
  }

  return buffer;
}

/**
 * Deserialize bytes to an encrypted payload
 * Matches C implementation: encryption.c::encrypted_payload_deserialize
 * @param {Uint8Array} bytes - The serialized payload
 * @returns {EncryptedPayload} - The deserialized payload
 */
export function deserializeEncryptedPayload(bytes) {
  const buffer = new Uint8Array(bytes);
  const view = new DataView(buffer.buffer);
  let offset = 0;

  // Read num_recipients (8 bytes, network byte order to match C backend)
  // eslint-disable-next-line no-undef
  const numRecipients = Number(ntohll(view.getBigUint64(offset, false)));
  offset += 8;

  // Read ciphertext_len (8 bytes, network byte order)
  // eslint-disable-next-line no-undef
  const ciphertextLen = Number(ntohll(view.getBigUint64(offset, false)));
  offset += 8;

  // Read ephemeral_pubkey (PUBKEY_SIZE bytes)
  const ephemeralPubkey = buffer.slice(offset, offset + PUBKEY_SIZE);
  offset += PUBKEY_SIZE;

  // Read nonce (24 bytes)
  const nonce = buffer.slice(offset, offset + sodium.crypto_secretbox_NONCEBYTES);
  offset += sodium.crypto_secretbox_NONCEBYTES;

  // Read ciphertext
  const ciphertext = buffer.slice(offset, offset + ciphertextLen);
  offset += ciphertextLen;

  // Read encrypted_keys (ENCRYPTED_KEY_SIZE = 48 bytes each)
  const encryptedKeys = [];
  for (let i = 0; i < numRecipients; i++) {
    const encryptedKey = buffer.slice(offset, offset + ENCRYPTED_KEY_SIZE);
    encryptedKeys.push(encryptedKey);
    offset += ENCRYPTED_KEY_SIZE;
  }

  // Read key_nonces (24 bytes each)
  const keyNonces = [];
  for (let i = 0; i < numRecipients; i++) {
    const keyNonce = buffer.slice(offset, offset + sodium.crypto_box_NONCEBYTES);
    keyNonces.push(keyNonce);
    offset += sodium.crypto_box_NONCEBYTES;
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
export async function encryptedPayloadToHex(payload) {
  await ensureSodiumReady();
  const bytes = serializeEncryptedPayload(payload);
  return sodium.to_hex(bytes);
}

/**
 * Convert hex string to encrypted payload
 * @param {string} hexString - Hex-encoded payload
 * @returns {EncryptedPayload} - The payload
 */
export async function encryptedPayloadFromHex(hexString) {
  await ensureSodiumReady();
  const bytes = sodium.from_hex(hexString);
  return deserializeEncryptedPayload(bytes);
}

export {
  EncryptedPayload,
  MAX_PLAINTEXT_SIZE,
  MAX_RECIPIENTS,
  ENCRYPTED_KEY_SIZE
};
