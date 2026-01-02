/**
 * Protobuf serialization helper for ClientRequest
 * Uses protobufjs to serialize JavaScript ClientRequest objects to protobuf binary format
 */

import protobuf from 'protobufjs';
import { hexToProtobuf, protobufToHex } from './protobufHelper';
import sodium from 'libsodium-wrappers';

let ClientRequestType = null;
let ClientRequestHeaderType = null;
let ClientRequestKeyWrapType = null;
let LocationUpdateType = null;

/**
 * Load protobuf schema for ClientRequest (lazy loading, cached)
 * @returns {Promise<Object>} Object with ClientRequestType, ClientRequestHeaderType, ClientRequestKeyWrapType, LocationUpdateType
 */
export async function loadClientRequestProtobufSchema() {
  if (ClientRequestType && ClientRequestHeaderType && ClientRequestKeyWrapType && LocationUpdateType) {
    return { ClientRequestType, ClientRequestHeaderType, ClientRequestKeyWrapType, LocationUpdateType };
  }

  try {
    // Define schema inline (more reliable than loading from file in browser)
    const protoDefinition = `
      syntax = "proto3";
      package tinyweb;
      
      message ClientRequestHeader {
        uint32 version = 1;
        uint32 content_type = 2;
        uint32 schema_version = 3;
        uint64 timestamp = 4;
        bytes sender_pubkey = 5;
        repeated bytes recipients_pubkey = 6;
        bytes group_id = 7;
      }
      
      message ClientRequestKeyWrap {
        bytes recipient_pubkey = 1;
        bytes key_nonce = 2;
        bytes wrapped_key = 3;
      }
      
      message ClientRequest {
        ClientRequestHeader header = 1;
        bytes payload_nonce = 2;
        bytes ephemeral_pubkey = 3;
        bytes payload_ciphertext = 4;
        repeated ClientRequestKeyWrap keywraps = 5;
        bytes signature = 6;
      }
      
      message LocationUpdate {
        double lat = 1;
        double lon = 2;
        uint32 accuracy_m = 3;
        uint64 timestamp = 4;
        string location_name = 5;
      }
    `;

    const root = protobuf.parse(protoDefinition, { keepCase: true }).root;
    ClientRequestType = root.lookupType('tinyweb.ClientRequest');
    ClientRequestHeaderType = root.lookupType('tinyweb.ClientRequestHeader');
    ClientRequestKeyWrapType = root.lookupType('tinyweb.ClientRequestKeyWrap');
    LocationUpdateType = root.lookupType('tinyweb.LocationUpdate');

    return { ClientRequestType, ClientRequestHeaderType, ClientRequestKeyWrapType, LocationUpdateType };
  } catch (error) {
    throw new Error(`Failed to load ClientRequest protobuf schema: ${error.message}`);
  }
}

/**
 * Compute ClientRequest digest for signing (matches backend logic exactly)
 * SHA256(domain || raw_header_fields || SHA256(ciphertext))
 * @param {Object} header - ClientRequestHeader object
 * @param {Uint8Array} ciphertext - Encrypted content
 * @returns {Promise<Uint8Array>} - SHA256 digest (32 bytes)
 */
async function computeClientRequestDigest(header, ciphertext) {
  await sodium.ready;
  
  // Create domain separator with null terminator (matches backend: "TWCLIENTREQ\0")
  const domain = new Uint8Array([84, 87, 67, 76, 73, 69, 78, 84, 82, 69, 81, 0]); // "TWCLIENTREQ\0"

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
  contentTypeView.setUint32(0, header.content_type, true);
  parts.push(contentTypeBytes);
  
  // 4. schema_version (uint32, 4 bytes, little-endian)
  const schemaVersionBytes = new Uint8Array(4);
  const schemaVersionView = new DataView(schemaVersionBytes.buffer);
  schemaVersionView.setUint32(0, header.schema_version, true);
  parts.push(schemaVersionBytes);
  
  // 5. timestamp (uint64, 8 bytes, little-endian)
  const timestampBytes = new Uint8Array(8);
  const timestampView = new DataView(timestampBytes.buffer);
  const timestampSeconds = header.timestamp;
  const low = timestampSeconds & 0xFFFFFFFF;
  const high = Math.floor(timestampSeconds / 0x100000000);
  timestampView.setUint32(0, low, true);  // little-endian
  timestampView.setUint32(4, high, true); // little-endian
  parts.push(timestampBytes);
  
  // 6. sender_pubkey (32 bytes)
  const senderPubkey = header.sender_pubkey instanceof Uint8Array 
    ? header.sender_pubkey 
    : new Uint8Array(header.sender_pubkey);
  if (senderPubkey.length !== 32) {
    throw new Error(`Invalid sender_pubkey length: ${senderPubkey.length}, expected 32`);
  }
  parts.push(senderPubkey);
  
  // 7. recipients_pubkey (count as uint32, then each 32-byte pubkey)
  const numRecipientsBytes = new Uint8Array(4);
  const numRecipientsView = new DataView(numRecipientsBytes.buffer);
  numRecipientsView.setUint32(0, header.recipients_pubkey.length, true);
  parts.push(numRecipientsBytes);
  
  for (const recipientPubkey of header.recipients_pubkey) {
    const pk = recipientPubkey instanceof Uint8Array 
      ? recipientPubkey 
      : new Uint8Array(recipientPubkey);
    if (pk.length !== 32) {
      throw new Error(`Invalid recipient_pubkey length: ${pk.length}, expected 32`);
    }
    parts.push(pk);
  }
  
  // 8. group_id (length as uint32, then data, or empty)
  const groupId = header.group_id && header.group_id.length > 0
    ? (header.group_id instanceof Uint8Array ? header.group_id : new Uint8Array(header.group_id))
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
 * Create a signed ClientRequest for a LocationUpdate
 * @param {Object} locationUpdate - LocationUpdate object with lat, lon, accuracy_m, timestamp, location_name
 * @param {Uint8Array[]} recipientPubkeys - Array of recipient Ed25519 public keys (32 bytes each)
 * @param {Function} encryptFunction - Function to encrypt payload (from encryption.js: encryptPayloadMulti)
 * @returns {Promise<Object>} ClientRequest object ready for serialization
 */
export async function createSignedClientRequest(locationUpdate, recipientPubkeys, encryptFunction) {
  await sodium.ready;
  const { LocationUpdateType } = await loadClientRequestProtobufSchema();
  
  // Create LocationUpdate protobuf
  const locationUpdateProto = {
    lat: locationUpdate.lat,
    lon: locationUpdate.lon,
    accuracy_m: locationUpdate.accuracy_m || 0,
    timestamp: locationUpdate.timestamp || Math.floor(Date.now() / 1000),
    location_name: locationUpdate.location_name || '',
  };
  
  const locationUpdateError = LocationUpdateType.verify(locationUpdateProto);
  if (locationUpdateError) {
    throw new Error(`Invalid LocationUpdate: ${locationUpdateError}`);
  }
  
  const locationUpdateMessage = LocationUpdateType.create(locationUpdateProto);
  const locationUpdateBytes = LocationUpdateType.encode(locationUpdateMessage).finish();
  
  // Convert Ed25519 recipient pubkeys to X25519 for encryption
  const encryptionPubkeys = recipientPubkeys.map(ed25519Pubkey => 
    sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519Pubkey)
  );
  
  // Encrypt the LocationUpdate payload (using X25519 keys)
  const encryptedPayload = await encryptFunction(new Uint8Array(locationUpdateBytes), encryptionPubkeys);
  
  // Get sender pubkey (from keystore)
  const keyStore = (await import('./keystore.js')).default;
  await keyStore.init();
  if (!keyStore.isKeypairLoaded()) {
    throw new Error('No keypair loaded. Please load or generate keys first.');
  }
  const senderPubkey = keyStore.getPublicKey();
  
  // Create ClientRequestHeader
  const timestamp = Math.floor(Date.now() / 1000);
  const header = {
    version: 1,
    content_type: 1, // CONTENT_LOCATION_UPDATE (from content.proto)
    schema_version: 1,
    timestamp: timestamp,
    sender_pubkey: senderPubkey,
    recipients_pubkey: recipientPubkeys.map(pk => pk instanceof Uint8Array ? pk : new Uint8Array(pk)),
    group_id: new Uint8Array(0), // Empty for direct messages
  };
  
  const { ClientRequestHeaderType } = await loadClientRequestProtobufSchema();
  const headerMessage = ClientRequestHeaderType.create(header);
  const headerError = ClientRequestHeaderType.verify(headerMessage);
  if (headerError) {
    throw new Error(`Invalid ClientRequestHeader: ${headerError}`);
  }
  
  // Create ClientRequestKeyWrap messages
  const { ClientRequestKeyWrapType } = await loadClientRequestProtobufSchema();
  const keywraps = [];
  
  if (encryptedPayload.encryptedKeys && encryptedPayload.keyNonces && recipientPubkeys) {
    for (let i = 0; i < recipientPubkeys.length; i++) {
      const recipientPubkey = recipientPubkeys[i];
      const keyNonce = encryptedPayload.keyNonces[i];
      const wrappedKey = encryptedPayload.encryptedKeys[i];
      
      const keywrap = {
        recipient_pubkey: recipientPubkey instanceof Uint8Array ? recipientPubkey : new Uint8Array(recipientPubkey),
        key_nonce: keyNonce instanceof Uint8Array ? keyNonce : new Uint8Array(keyNonce),
        wrapped_key: wrappedKey instanceof Uint8Array ? wrappedKey : new Uint8Array(wrappedKey),
      };
      
      const keywrapMessage = ClientRequestKeyWrapType.create(keywrap);
      const keywrapError = ClientRequestKeyWrapType.verify(keywrapMessage);
      if (keywrapError) {
        throw new Error(`Invalid keywrap ${i}: ${keywrapError}`);
      }
      
      keywraps.push(keywrapMessage);
    }
  }
  
  // Compute signing digest (matches backend: client_request_validation.c::compute_client_request_signing_digest)
  // SHA256(domain || raw_header_fields || SHA256(ciphertext))
  const digest = await computeClientRequestDigest(header, encryptedPayload.ciphertext);
  
  // Sign the digest using keystore
  const privateKey = keyStore._getPrivateKey();
  const signature = sodium.crypto_sign_detached(digest, privateKey);
  
  // Create ClientRequest message
  const clientRequestProto = {
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
    signature: signature instanceof Uint8Array
      ? signature
      : new Uint8Array(signature),
  };
  
  // Validate ClientRequest
  const { ClientRequestType } = await loadClientRequestProtobufSchema();
  const requestError = ClientRequestType.verify(clientRequestProto);
  if (requestError) {
    throw new Error(`Invalid ClientRequest: ${requestError}`);
  }
  
  return {
    header: header,
    encryptedPayload: encryptedPayload,
    signature: signature,
  };
}

/**
 * Serialize ClientRequest to protobuf binary
 * @param {Object} clientRequest - JavaScript ClientRequest object (from createSignedClientRequest)
 * @returns {Promise<Uint8Array>} Protobuf-encoded ClientRequest bytes
 */
export async function serializeClientRequestToProtobuf(clientRequest) {
  const { ClientRequestType, ClientRequestHeaderType, ClientRequestKeyWrapType } = await loadClientRequestProtobufSchema();
  
  // Reconstruct header message
  const headerMessage = ClientRequestHeaderType.create(clientRequest.header);
  const headerError = ClientRequestHeaderType.verify(headerMessage);
  if (headerError) {
    throw new Error(`Invalid ClientRequestHeader: ${headerError}`);
  }
  
  // Reconstruct keywraps
  const keywraps = [];
  const encryptedPayload = clientRequest.encryptedPayload;
  
  if (encryptedPayload.encryptedKeys && encryptedPayload.keyNonces && clientRequest.header.recipients_pubkey) {
    for (let i = 0; i < clientRequest.header.recipients_pubkey.length; i++) {
      const recipientPubkey = clientRequest.header.recipients_pubkey[i];
      const keyNonce = encryptedPayload.keyNonces[i];
      const wrappedKey = encryptedPayload.encryptedKeys[i];
      
      const keywrap = {
        recipient_pubkey: recipientPubkey instanceof Uint8Array ? recipientPubkey : new Uint8Array(recipientPubkey),
        key_nonce: keyNonce instanceof Uint8Array ? keyNonce : new Uint8Array(keyNonce),
        wrapped_key: wrappedKey instanceof Uint8Array ? wrappedKey : new Uint8Array(wrappedKey),
      };
      
      const keywrapMessage = ClientRequestKeyWrapType.create(keywrap);
      const keywrapError = ClientRequestKeyWrapType.verify(keywrapMessage);
      if (keywrapError) {
        throw new Error(`Invalid keywrap ${i}: ${keywrapError}`);
      }
      
      keywraps.push(keywrapMessage);
    }
  }
  
  // Create ClientRequest message
  const requestProto = {
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
    signature: clientRequest.signature instanceof Uint8Array
      ? clientRequest.signature
      : new Uint8Array(clientRequest.signature),
  };
  
  // Validate ClientRequest
  const requestError = ClientRequestType.verify(requestProto);
  if (requestError) {
    throw new Error(`Invalid ClientRequest: ${requestError}`);
  }
  
  // Encode to binary
  const requestObj = ClientRequestType.create(requestProto);
  const buffer = ClientRequestType.encode(requestObj).finish();
  
  return new Uint8Array(buffer);
}

/**
 * Serialize ClientRequest to protobuf and convert to hex string
 * @param {Object} clientRequest - JavaScript ClientRequest object
 * @returns {Promise<string>} Hex-encoded protobuf-serialized ClientRequest
 */
export async function serializeClientRequestToProtobufHex(clientRequest) {
  const protobufBytes = await serializeClientRequestToProtobuf(clientRequest);
  return protobufToHex(protobufBytes);
}

/**
 * Deserialize protobuf-encoded ClientRequest bytes to a JS object compatible with decryptPayload()
 * @param {Uint8Array|string} requestBytes - Protobuf-encoded ClientRequest (Uint8Array or hex string)
 * @returns {Promise<Object>} { header, encryptedPayload, signature }
 */
export async function deserializeClientRequestFromProtobuf(requestBytes) {
  const { ClientRequestType } = await loadClientRequestProtobufSchema();

  let bytes = requestBytes;
  if (typeof requestBytes === 'string') {
    bytes = hexToProtobuf(requestBytes);
  }

  const req = ClientRequestType.decode(bytes);

  const header = {
    version: req.header.version,
    content_type: req.header.content_type,
    schema_version: req.header.schema_version,
    timestamp: Number(req.header.timestamp),
    sender_pubkey: new Uint8Array(req.header.sender_pubkey),
    recipients_pubkey: (req.header.recipients_pubkey || []).map(pk => new Uint8Array(pk)),
    group_id: req.header.group_id && req.header.group_id.length > 0 ? new Uint8Array(req.header.group_id) : new Uint8Array(0),
  };

  const { EncryptedPayload } = await import('./encryption.js');
  const encryptedPayload = new EncryptedPayload();
  encryptedPayload.ciphertext = new Uint8Array(req.payload_ciphertext);
  encryptedPayload.nonce = new Uint8Array(req.payload_nonce);
  encryptedPayload.ephemeralPubkey = new Uint8Array(req.ephemeral_pubkey);
  encryptedPayload.numRecipients = header.recipients_pubkey.length;

  // Map keywraps by recipient pubkey (ed25519) hex for stable matching
  const keywrapMap = new Map();
  for (const keywrap of (req.keywraps || [])) {
    const recipientKey = new Uint8Array(keywrap.recipient_pubkey);
    const keyHex = Array.from(recipientKey).map(b => b.toString(16).padStart(2, '0')).join('');
    keywrapMap.set(keyHex, keywrap);
  }

  encryptedPayload.encryptedKeys = [];
  encryptedPayload.keyNonces = [];
  for (const recipientPubkey of header.recipients_pubkey) {
    const keyHex = Array.from(recipientPubkey).map(b => b.toString(16).padStart(2, '0')).join('');
    const keywrap = keywrapMap.get(keyHex);
    if (keywrap) {
      encryptedPayload.encryptedKeys.push(new Uint8Array(keywrap.wrapped_key));
      encryptedPayload.keyNonces.push(new Uint8Array(keywrap.key_nonce));
    } else {
      encryptedPayload.encryptedKeys.push(new Uint8Array(0));
      encryptedPayload.keyNonces.push(new Uint8Array(0));
    }
  }

  const signature = new Uint8Array(req.signature);

  return { header, encryptedPayload, signature };
}

