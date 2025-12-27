import sodium from 'libsodium-wrappers';
import keyStore from './keystore.js';
import { encryptPayloadMulti } from './encryption.js';
import { loadMessageProtobufSchema } from './messageHelper.js';

/**
 * Frontend message utility - mirrors backend message logic
 * Handles Message structure, encryption, and signing for user-to-user messaging
 * Uses "TWMESSAGE\0" domain separator (different from Envelope's "TWENVELOPE\0")
 */

// Ensure sodium is ready before use
async function ensureSodiumReady() {
  await sodium.ready;
}

// Message header structure
export class MessageHeader {
  constructor() {
    this.version = 1;
    this.timestamp = Math.floor(Date.now() / 1000); // UNIX epoch seconds
    this.senderPubkey = null; // Will be set from keystore
    this.recipientsPubkey = [];
    this.groupId = null;
  }
}

/**
 * Create and sign a message with encrypted content
 * @param {MessageHeader} header - The message header
 * @param {Uint8Array} plaintext - The message content
 * @returns {Object} - Signed message object
 */
export async function createSignedMessage(header, plaintext) {
  await ensureSodiumReady();
  
  if (!header.senderPubkey) {
    header.senderPubkey = keyStore.getPublicKey();
  }

  // Convert Ed25519 recipient pubkeys to X25519 for encryption
  const encryptionPubkeys = header.recipientsPubkey.map(ed25519Pubkey => 
    sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519Pubkey)
  );

  // Encrypt the message for all recipients (using X25519 keys)
  const encrypted = await encryptPayloadMulti(plaintext, encryptionPubkeys);

  // Create message structure
  const message = {
    header: {
      version: header.version,
      timestamp: header.timestamp, // Already in seconds
      senderPubkey: header.senderPubkey,
      recipientsPubkey: header.recipientsPubkey,
      groupId: header.groupId
    },
    encryptedPayload: encrypted,
    signature: null
  };

  // Compute digest and sign
  const digest = await computeMessageDigest(message.header, encrypted.ciphertext);
  message.signature = await signDigest(digest);

  return message;
}

/**
 * Compute message digest for signing (matches backend logic exactly)
 * Uses raw header data (not protobuf-serialized) for cleaner digest computation
 * Backend uses: SHA256(domain || raw_header_fields || SHA256(ciphertext))
 * @param {Object} header - Message header
 * @param {Uint8Array} ciphertext - Encrypted content
 * @returns {Promise<Uint8Array>} - SHA256 digest (32 bytes)
 */
export async function computeMessageDigest(header, ciphertext) {
  await ensureSodiumReady();
  
  // Create domain separator with null terminator (matches backend: "TWMESSAGE\0")
  const domain = new Uint8Array([84, 87, 77, 69, 83, 83, 65, 71, 69, 0]); // "TWMESSAGE\0"

  // Hash ciphertext with SHA256 first
  const payloadHash = await sha256(ciphertext);

  // Build digest from raw header fields (canonical order matching backend)
  const parts = [];
  
  // 1. Domain
  parts.push(domain);
  
  // 2. version (uint32, 4 bytes, little-endian)
  const versionBytes = new Uint8Array(4);
  const versionView = new DataView(versionBytes.buffer);
  versionView.setUint32(0, header.version, true); // little-endian
  parts.push(versionBytes);
  
  // 3. timestamp (uint64, 8 bytes, little-endian) - already in seconds
  const timestampBytes = new Uint8Array(8);
  const timestampView = new DataView(timestampBytes.buffer);
  const timestampSeconds = header.timestamp; // Already in seconds
  // Use setUint32 for 64-bit value (split into two 32-bit parts for compatibility)
  const low = timestampSeconds & 0xFFFFFFFF;
  const high = Math.floor(timestampSeconds / 0x100000000);
  timestampView.setUint32(0, low, true);  // little-endian
  timestampView.setUint32(4, high, true); // little-endian
  parts.push(timestampBytes);
  
  // 4. sender_pubkey (32 bytes)
  const senderPubkey = header.senderPubkey instanceof Uint8Array 
    ? header.senderPubkey 
    : new Uint8Array(header.senderPubkey);
  if (senderPubkey.length !== 32) {
    throw new Error(`Invalid sender_pubkey length: ${senderPubkey.length}, expected 32`);
  }
  parts.push(senderPubkey);
  
  // 5. recipients_pubkey (count as uint32, then each 32-byte pubkey)
  const numRecipientsBytes = new Uint8Array(4);
  const numRecipientsView = new DataView(numRecipientsBytes.buffer);
  numRecipientsView.setUint32(0, header.recipientsPubkey.length, true);
  parts.push(numRecipientsBytes);
  
  for (const recipientPubkey of header.recipientsPubkey) {
    const pk = recipientPubkey instanceof Uint8Array 
      ? recipientPubkey 
      : new Uint8Array(recipientPubkey);
    if (pk.length !== 32) {
      throw new Error(`Invalid recipient_pubkey length: ${pk.length}, expected 32`);
    }
    parts.push(pk);
  }
  
  // 6. group_id (length as uint32, then data, or empty)
  const groupId = header.groupId 
    ? (header.groupId instanceof Uint8Array ? header.groupId : new Uint8Array(header.groupId))
    : new Uint8Array(0);
  const groupIdLenBytes = new Uint8Array(4);
  const groupIdLenView = new DataView(groupIdLenBytes.buffer);
  groupIdLenView.setUint32(0, groupId.length, true);
  parts.push(groupIdLenBytes);
  if (groupId.length > 0) {
    parts.push(groupId);
  }
  
  // 7. Payload hash
  parts.push(payloadHash);
  
  // Combine all parts and hash
  const totalLength = parts.reduce((sum, part) => sum + part.length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    combined.set(part, offset);
    offset += part.length;
  }
  
  return await sha256(combined);
}

/**
 * Compute SHA256 hash (using Web Crypto API for compatibility)
 * @param {Uint8Array} data - Data to hash
 * @returns {Promise<Uint8Array>} - SHA256 hash (32 bytes)
 */
async function sha256(data) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hashBuffer);
}

/**
 * Sign a digest using the keystore
 * @param {Uint8Array} digest - The digest to sign
 * @returns {Uint8Array} - The signature
 */
async function signDigest(digest) {
  await ensureSodiumReady();
  const privateKey = keyStore._getPrivateKey();
  return sodium.crypto_sign_detached(digest, privateKey);
}

/**
 * Verify a message signature
 * @param {Object} message - The message to verify
 * @returns {Promise<boolean>} - Whether signature is valid
 */
export async function verifyMessageSignature(message) {
  await ensureSodiumReady();
  
  const digest = await computeMessageDigest(message.header, message.encryptedPayload.ciphertext);
  
  try {
    const result = sodium.crypto_sign_verify_detached(
      message.signature,
      digest,
      message.header.senderPubkey
    );
    return result;
  } catch (err) {
    console.error('crypto_sign_verify_detached error:', err);
    throw err;
  }
}

/**
 * Create a direct message
 * @param {Uint8Array} recipientPubkey - Recipient's public key
 * @param {string} messageText - The message text
 * @returns {Object} - Signed message
 */
export async function createDirectMessage(recipientPubkey, messageText) {
  const header = new MessageHeader();
  header.recipientsPubkey = [recipientPubkey];

  const plaintext = new TextEncoder().encode(messageText);
  return await createSignedMessage(header, plaintext);
}

/**
 * Create a group message
 * @param {Uint8Array[]} recipientPubkeys - Array of recipient public keys
 * @param {string} messageText - The message text
 * @param {Uint8Array} groupId - Optional group identifier
 * @returns {Object} - Signed message
 */
export async function createGroupMessage(recipientPubkeys, messageText, groupId = null) {
  const header = new MessageHeader();
  header.recipientsPubkey = recipientPubkeys;
  header.groupId = groupId;

  const plaintext = new TextEncoder().encode(messageText);
  return await createSignedMessage(header, plaintext);
}


