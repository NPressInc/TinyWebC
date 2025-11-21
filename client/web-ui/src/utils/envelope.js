import sodium from 'libsodium-wrappers';
import keyStore from './keystore.js';
import { encryptPayloadMulti, encryptedPayloadToHex } from './encryption.js';

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
 * Compute envelope digest for signing (matches backend logic)
 * @param {Object} header - Envelope header
 * @param {Uint8Array} ciphertext - Encrypted content
 * @returns {Uint8Array} - SHA256 digest
 */
async function computeEnvelopeDigest(header, ciphertext) {
  await ensureSodiumReady();
  
  // Create domain separator
  const domain = new Uint8Array([84, 87, 69, 78, 86, 69, 76, 79, 80, 69]); // "TWENVELOPE"

  // Serialize header (simplified - in production would use proper protobuf)
  // Convert timestamp to bytes manually (little-endian)
  const timestampBytes = new Uint8Array(8);
  let timestamp = header.timestamp;
  for (let i = 0; i < 8; i++) {
    timestampBytes[i] = timestamp & 0xff;
    timestamp >>= 8;
  }

  const headerData = new Uint8Array([
    header.version,
    header.contentType,
    header.schemaVersion,
    ...timestampBytes,
    ...header.senderPubkey,
    ...header.recipientPubkeys.flatMap(pk => Array.from(pk))
  ]);

  // Hash ciphertext
  const contentHash = sodium.crypto_generichash(sodium.crypto_generichash_BYTES, ciphertext);

  // Combine everything
  const combined = new Uint8Array([
    ...domain,
    ...headerData,
    ...contentHash
  ]);

  return sodium.crypto_generichash(sodium.crypto_generichash_BYTES, combined);
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
