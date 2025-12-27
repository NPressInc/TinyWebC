/**
 * Protobuf serialization helper for envelopes
 * Uses protobufjs to serialize JavaScript envelope objects to protobuf binary format
 */

import protobuf from 'protobufjs';

let EnvelopeType = null;
let EnvelopeHeaderType = null;
let RecipientKeyWrapType = null;

/**
 * Load protobuf schema (lazy loading, cached)
 */
export async function loadProtobufSchema() {
  if (EnvelopeType) {
    return { EnvelopeType, EnvelopeHeaderType, RecipientKeyWrapType };
  }

  try {
    // Define schema inline (more reliable than loading from file in browser)
    const protoDefinition = `
      syntax = "proto3";
      package tinyweb;
      
      enum ContentType {
        CONTENT_UNKNOWN = 0;
        // NOTE: DirectMessage and GroupMessage (10-11) have been moved to the
        // separate Message system. Envelopes are for system messages only.
        CONTENT_LOCATION_UPDATE = 33;
        CONTENT_EMERGENCY_ALERT = 34;
      }
      
      message EnvelopeHeader {
        uint32 version = 1;
        uint32 content_type = 2;
        uint32 schema_version = 3;
        uint64 timestamp = 4;
        bytes sender_pubkey = 5;
        repeated bytes recipients_pubkey = 6;
        bytes group_id = 7;
      }
      
      message RecipientKeyWrap {
        bytes recipient_pubkey = 1;
        bytes key_nonce = 2;
        bytes wrapped_key = 3;
      }
      
      message Envelope {
        EnvelopeHeader header = 1;
        bytes payload_nonce = 2;
        bytes ephemeral_pubkey = 3;
        bytes payload_ciphertext = 4;
        repeated RecipientKeyWrap keywraps = 5;
        bytes signature = 6;
      }
    `;
    
    const root = protobuf.parse(protoDefinition, { keepCase: true }).root;
    
    EnvelopeType = root.lookupType('tinyweb.Envelope');
    EnvelopeHeaderType = root.lookupType('tinyweb.EnvelopeHeader');
    RecipientKeyWrapType = root.lookupType('tinyweb.RecipientKeyWrap');
    
    if (!EnvelopeType || !EnvelopeHeaderType || !RecipientKeyWrapType) {
      throw new Error('Failed to load protobuf types');
    }
    
    return { EnvelopeType, EnvelopeHeaderType, RecipientKeyWrapType };
  } catch (error) {
    throw new Error(`Failed to load protobuf schema: ${error.message}`);
  }
}

/**
 * Serialize a JavaScript envelope object to protobuf binary format
 * @param {Object} envelope - JavaScript envelope object from createSignedEnvelope()
 * @returns {Promise<Uint8Array>} Protobuf-serialized envelope as binary
 */
export async function serializeEnvelopeToProtobuf(envelope) {
  const { EnvelopeType, EnvelopeHeaderType, RecipientKeyWrapType } = await loadProtobufSchema();
  
  // Create EnvelopeHeader
  // Note: protobufjs accepts Uint8Array or regular arrays for bytes fields
  const header = {
    version: envelope.header.version,
    content_type: envelope.header.contentType,
    schema_version: envelope.header.schemaVersion,
    timestamp: Math.floor(envelope.header.timestamp / 1000), // Convert ms to seconds (protobuf uint64)
    sender_pubkey: envelope.header.senderPubkey instanceof Uint8Array 
      ? envelope.header.senderPubkey 
      : new Uint8Array(envelope.header.senderPubkey),
    recipients_pubkey: envelope.header.recipientPubkeys.map(pk => 
      pk instanceof Uint8Array ? pk : new Uint8Array(pk)
    ),
    group_id: envelope.header.groupId 
      ? (envelope.header.groupId instanceof Uint8Array ? envelope.header.groupId : new Uint8Array(envelope.header.groupId))
      : new Uint8Array(0),
  };
  
  // Validate and create header message
  const headerMessage = EnvelopeHeaderType.create(header);
  const headerError = EnvelopeHeaderType.verify(headerMessage);
  if (headerError) {
    throw new Error(`Invalid envelope header: ${headerError}`);
  }
  
  // Create RecipientKeyWrap messages
  // Note: The encryptedPayload structure has encryptedKeys and keyNonces arrays
  // We need to map these to keywraps, matching recipientPubkeys order
  const keywraps = [];
  const encryptedPayload = envelope.encryptedPayload;
  
  if (encryptedPayload.encryptedKeys && encryptedPayload.keyNonces) {
    for (let i = 0; i < envelope.header.recipientPubkeys.length; i++) {
      const recipientPubkey = envelope.header.recipientPubkeys[i];
      const keyNonce = encryptedPayload.keyNonces[i];
      const wrappedKey = encryptedPayload.encryptedKeys[i];
      
      const keywrap = {
        recipient_pubkey: recipientPubkey instanceof Uint8Array ? recipientPubkey : new Uint8Array(recipientPubkey),
        key_nonce: keyNonce instanceof Uint8Array ? keyNonce : new Uint8Array(keyNonce),
        wrapped_key: wrappedKey instanceof Uint8Array ? wrappedKey : new Uint8Array(wrappedKey),
      };
      
      const keywrapMessage = RecipientKeyWrapType.create(keywrap);
      const keywrapError = RecipientKeyWrapType.verify(keywrapMessage);
      if (keywrapError) {
        throw new Error(`Invalid keywrap ${i}: ${keywrapError}`);
      }
      
      keywraps.push(keywrapMessage);
    }
  }
  
  // Create Envelope message
  const envelopeMessage = {
    header: headerMessage,
    payload_nonce: encryptedPayload.nonce instanceof Uint8Array 
      ? encryptedPayload.nonce 
      : new Uint8Array(encryptedPayload.nonce),
    ephemeral_pubkey: encryptedPayload.ephemeralPubkey instanceof Uint8Array
      ? encryptedPayload.ephemeralPubkey
      : new Uint8Array(encryptedPayload.ephemeralPubkey),
    payload_ciphertext: encryptedPayload.ciphertext instanceof Uint8Array
      ? encryptedPayload.ciphertext
      : new Uint8Array(encryptedPayload.ciphertext),
    keywraps: keywraps,
    signature: envelope.signature instanceof Uint8Array
      ? envelope.signature
      : new Uint8Array(envelope.signature),
  };
  
  // Validate envelope
  const envelopeError = EnvelopeType.verify(envelopeMessage);
  if (envelopeError) {
    throw new Error(`Invalid envelope: ${envelopeError}`);
  }
  
  // Encode to binary
  const message = EnvelopeType.create(envelopeMessage);
  const buffer = EnvelopeType.encode(message).finish();
  
  return new Uint8Array(buffer);
}

/**
 * Serialize envelope to protobuf and convert to hex string
 * @param {Object} envelope - JavaScript envelope object
 * @returns {Promise<string>} Hex-encoded protobuf-serialized envelope
 */
export async function serializeEnvelopeToProtobufHex(envelope) {
  const protobufBytes = await serializeEnvelopeToProtobuf(envelope);
  return protobufToHex(protobufBytes);
}

/**
 * Convert protobuf-serialized envelope to hex string
 * @param {Uint8Array} protobufBytes - Protobuf-serialized envelope
 * @returns {string} Hex-encoded string
 */
export function protobufToHex(protobufBytes) {
  // Simple hex encoding
  return Array.from(protobufBytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to Uint8Array
 * @param {string} hex - Hex-encoded string
 * @returns {Uint8Array} Binary data
 */
export function hexToProtobuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Deserialize protobuf-encoded envelope bytes to JavaScript object
 * @param {Uint8Array|string} envelopeBytes - Protobuf-encoded envelope (Uint8Array or hex string)
 * @returns {Promise<Object>} Decoded envelope object with header, encryptedPayload, and signature
 */
export async function deserializeEnvelopeFromProtobuf(envelopeBytes) {
  const { EnvelopeType } = await loadProtobufSchema();
  
  // Convert hex string to Uint8Array if needed
  let bytes = envelopeBytes;
  if (typeof envelopeBytes === 'string') {
    bytes = hexToProtobuf(envelopeBytes);
  }
  
  // Decode protobuf message
  const message = EnvelopeType.decode(bytes);
  
  // Extract header
  const header = {
    version: message.header.version,
    contentType: message.header.content_type,
    schemaVersion: message.header.schema_version,
    timestamp: Number(message.header.timestamp) * 1000, // Convert seconds to ms
    senderPubkey: new Uint8Array(message.header.sender_pubkey),
    recipientPubkeys: (message.header.recipients_pubkey || []).map(pk => new Uint8Array(pk)),
    groupId: message.header.group_id ? new Uint8Array(message.header.group_id) : null,
  };
  
  // Extract encrypted payload structure
  const { EncryptedPayload } = await import('./encryption.js');
  const encryptedPayload = new EncryptedPayload();
  encryptedPayload.ciphertext = new Uint8Array(message.payload_ciphertext);
  encryptedPayload.nonce = new Uint8Array(message.payload_nonce);
  encryptedPayload.ephemeralPubkey = new Uint8Array(message.ephemeral_pubkey);
  
  // Extract keywraps and map to encryptedKeys/keyNonces arrays
  // Match keywraps to recipientPubkeys by comparing pubkeys
  encryptedPayload.encryptedKeys = [];
  encryptedPayload.keyNonces = [];
  encryptedPayload.numRecipients = header.recipientPubkeys.length;
  
  // Create a map of recipient pubkey to keywrap
  const keywrapMap = new Map();
  for (const keywrap of (message.keywraps || [])) {
    const recipientKey = Array.from(keywrap.recipient_pubkey);
    keywrapMap.set(recipientKey.join(','), keywrap);
  }
  
  // Match keywraps to recipientPubkeys in order
  for (const recipientPubkey of header.recipientPubkeys) {
    const key = Array.from(recipientPubkey).join(',');
    const keywrap = keywrapMap.get(key);
    if (keywrap) {
      encryptedPayload.encryptedKeys.push(new Uint8Array(keywrap.wrapped_key));
      encryptedPayload.keyNonces.push(new Uint8Array(keywrap.key_nonce));
    } else {
      throw new Error(`Keywrap not found for recipient pubkey`);
    }
  }
  
  // Extract signature
  const signature = new Uint8Array(message.signature);
  
  return {
    header,
    encryptedPayload,
    signature,
  };
}




