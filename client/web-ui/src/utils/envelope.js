import sodium from 'libsodium-wrappers';
import keyStore from './keystore.js';
import { encryptPayloadMulti, encryptedPayloadToHex } from './encryption.js';
import { loadProtobufSchema } from './protobufHelper.js';

/**
 * Frontend envelope utility - mirrors backend envelope logic
 * Handles message structure, encryption, and signing
 */

// Ensure sodium is ready before use
async function ensureSodiumReady() {
  await sodium.ready;
}

// Content types matching backend
export const CONTENT_TYPE = {
  DIRECT_MESSAGE: 1,
  GROUP_MESSAGE: 2,
  LOCATION_UPDATE: 3,
  EMERGENCY_ALERT: 4
};

// Envelope header structure
export class EnvelopeHeader {
  constructor() {
    this.version = 1;
    this.contentType = CONTENT_TYPE.DIRECT_MESSAGE;
    this.schemaVersion = 1;
    this.timestamp = Date.now();
    this.senderPubkey = null; // Will be set from keystore
    this.recipientPubkeys = [];
    this.groupId = null;
  }
}

/**
 * Create and sign an envelope with encrypted content
 * @param {EnvelopeHeader} header - The envelope header
 * @param {Uint8Array} plaintext - The message content
 * @returns {Object} - Signed envelope object
 */
export async function createSignedEnvelope(header, plaintext) {
  await ensureSodiumReady();
  
  if (!header.senderPubkey) {
    header.senderPubkey = keyStore.getPublicKey();
  }

  // Convert Ed25519 recipient pubkeys to X25519 for encryption
  const encryptionPubkeys = header.recipientPubkeys.map(ed25519Pubkey => 
    sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519Pubkey)
  );

  // Encrypt the message for all recipients (using X25519 keys)
  const encrypted = await encryptPayloadMulti(plaintext, encryptionPubkeys);

  // Create envelope structure
  const envelope = {
    header: {
      version: header.version,
      contentType: header.contentType,
      schemaVersion: header.schemaVersion,
      timestamp: header.timestamp,
      senderPubkey: header.senderPubkey,
      recipientPubkeys: header.recipientPubkeys,
      groupId: header.groupId
    },
    encryptedPayload: encrypted,
    signature: null
  };

  // Compute digest and sign
  const digest = await computeEnvelopeDigest(envelope.header, encrypted.ciphertext);
  envelope.signature = await signDigest(digest);

  return envelope;
}

/**
 * Compute envelope digest for signing (matches backend logic exactly)
 * Uses raw header data (not protobuf-serialized) for cleaner digest computation
 * Backend uses: SHA256(domain || raw_header_fields || SHA256(ciphertext))
 * @param {Object} header - Envelope header
 * @param {Uint8Array} ciphertext - Encrypted content
 * @returns {Promise<Uint8Array>} - SHA256 digest (32 bytes)
 */
async function computeEnvelopeDigest(header, ciphertext) {
  await ensureSodiumReady();
  
  // Create domain separator with null terminator (matches backend: "TWENVELOPE\0")
  const domain = new Uint8Array([84, 87, 69, 78, 86, 69, 76, 79, 80, 69, 0]); // "TWENVELOPE\0"

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
  
  // 3. content_type (uint32, 4 bytes, little-endian)
  const contentTypeBytes = new Uint8Array(4);
  const contentTypeView = new DataView(contentTypeBytes.buffer);
  contentTypeView.setUint32(0, header.contentType, true);
  parts.push(contentTypeBytes);
  
  // 4. schema_version (uint32, 4 bytes, little-endian)
  const schemaVersionBytes = new Uint8Array(4);
  const schemaVersionView = new DataView(schemaVersionBytes.buffer);
  schemaVersionView.setUint32(0, header.schemaVersion, true);
  parts.push(schemaVersionBytes);
  
  // 5. timestamp (uint64, 8 bytes, little-endian) - convert ms to seconds
  const timestampBytes = new Uint8Array(8);
  const timestampView = new DataView(timestampBytes.buffer);
  const timestampSeconds = Math.floor(header.timestamp / 1000);
  // Use setUint32 for 64-bit value (split into two 32-bit parts for compatibility)
  // JavaScript numbers are safe up to 2^53, so we can use this approach
  const low = timestampSeconds & 0xFFFFFFFF;
  const high = Math.floor(timestampSeconds / 0x100000000);
  timestampView.setUint32(0, low, true);  // little-endian
  timestampView.setUint32(4, high, true); // little-endian
  parts.push(timestampBytes);
  
  // 6. sender_pubkey (32 bytes)
  const senderPubkey = header.senderPubkey instanceof Uint8Array 
    ? header.senderPubkey 
    : new Uint8Array(header.senderPubkey);
  if (senderPubkey.length !== 32) {
    throw new Error(`Invalid sender_pubkey length: ${senderPubkey.length}, expected 32`);
  }
  parts.push(senderPubkey);
  
  // 7. recipients_pubkey (count as uint32, then each 32-byte pubkey)
  const numRecipientsBytes = new Uint8Array(4);
  const numRecipientsView = new DataView(numRecipientsBytes.buffer);
  numRecipientsView.setUint32(0, header.recipientPubkeys.length, true);
  parts.push(numRecipientsBytes);
  
  for (const recipientPubkey of header.recipientPubkeys) {
    const pk = recipientPubkey instanceof Uint8Array 
      ? recipientPubkey 
      : new Uint8Array(recipientPubkey);
    if (pk.length !== 32) {
      throw new Error(`Invalid recipient_pubkey length: ${pk.length}, expected 32`);
    }
    parts.push(pk);
  }
  
  // 8. group_id (length as uint32, then data, or empty)
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
  
  // 9. Payload hash
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
 * Verify an envelope signature
 * @param {Object} envelope - The envelope to verify
 * @returns {boolean} - Whether signature is valid
 */
export async function verifyEnvelopeSignature(envelope) {
  await ensureSodiumReady();
  
  console.log('🔍 verifyEnvelopeSignature called');
  console.log('📦 Envelope:', envelope);
  console.log('📋 Header:', envelope.header);
  console.log('👤 Sender pubkey:', envelope.header.senderPubkey);
  console.log('👤 Sender pubkey type:', envelope.header.senderPubkey?.constructor?.name);
  console.log('👤 Sender pubkey length:', envelope.header.senderPubkey?.length);
  console.log('🔑 Signature:', envelope.signature);
  console.log('🔑 Signature type:', envelope.signature?.constructor?.name);
  console.log('🔑 Signature length:', envelope.signature?.length);
  
  const digest = await computeEnvelopeDigest(envelope.header, envelope.encryptedPayload.ciphertext);
  console.log('🔐 Computed digest:', digest);
  console.log('🔐 Digest length:', digest?.length);
  
  try {
    const result = sodium.crypto_sign_verify_detached(
      envelope.signature,
      digest,
      envelope.header.senderPubkey
    );
    console.log('✅ Verification result:', result);
    return result;
  } catch (err) {
    console.error('❌ crypto_sign_verify_detached error:', err);
    throw err;
  }
}

/**
 * Convert envelope to transaction format for API submission
 * @param {Object} envelope - The signed envelope
 * @returns {Object} - Transaction data ready for API
 */
export async function envelopeToTransaction(envelope) {
  await ensureSodiumReady();
  
  // Serialize the envelope (simplified - in production would use protobuf)
  const envelopeData = {
    header: envelope.header,
    encryptedPayloadHex: await encryptedPayloadToHex(envelope.encryptedPayload),
    signatureHex: sodium.to_hex(envelope.signature)
  };

  // Convert to the format expected by the backend API
  const transaction = {
    type: getTransactionTypeForContent(envelope.header.contentType),
    sender: sodium.to_hex(envelope.header.senderPubkey),
    timestamp: envelope.header.timestamp,
    recipients: envelope.header.recipientPubkeys.map(pk => sodium.to_hex(pk)),
    recipientCount: envelope.header.recipientPubkeys.length,
    payload: envelopeData, // This would be serialized properly in production
    signature: envelope.signature
  };

  return transaction;
}

/**
 * Convert content type to transaction type
 * @param {number} contentType - Envelope content type
 * @returns {number} - Transaction type
 */
function getTransactionTypeForContent(contentType) {
  switch (contentType) {
    case CONTENT_TYPE.DIRECT_MESSAGE:
    case CONTENT_TYPE.GROUP_MESSAGE:
      return 23; // TW_TXN_MESSAGE or TW_TXN_GROUP_MESSAGE
    case CONTENT_TYPE.LOCATION_UPDATE:
      return 37; // TW_TXN_LOCATION_UPDATE
    case CONTENT_TYPE.EMERGENCY_ALERT:
      return 38; // TW_TXN_EMERGENCY_ALERT
    default:
      return 23; // Default to message
  }
}

/**
 * Create a direct message envelope
 * @param {Uint8Array} recipientPubkey - Recipient's public key
 * @param {string} message - The message text
 * @returns {Object} - Signed envelope
 */
export async function createDirectMessage(recipientPubkey, message) {
  const header = new EnvelopeHeader();
  header.contentType = CONTENT_TYPE.DIRECT_MESSAGE;
  header.recipientPubkeys = [recipientPubkey];

  const plaintext = new TextEncoder().encode(message);
  return await createSignedEnvelope(header, plaintext);
}

/**
 * Create a group message envelope
 * @param {Uint8Array[]} recipientPubkeys - Array of recipient public keys
 * @param {string} message - The message text
 * @param {Uint8Array} groupId - Optional group identifier
 * @returns {Object} - Signed envelope
 */
export async function createGroupMessage(recipientPubkeys, message, groupId = null) {
  const header = new EnvelopeHeader();
  header.contentType = CONTENT_TYPE.GROUP_MESSAGE;
  header.recipientPubkeys = recipientPubkeys;
  header.groupId = groupId;

  const plaintext = new TextEncoder().encode(message);
  return await createSignedEnvelope(header, plaintext);
}
