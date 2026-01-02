/**
 * Protobuf helper for Envelope decoding in the browser
 * We keep the schema inline (same approach as messageHelper/clientRequestHelper).
 */

import protobuf from 'protobufjs';
import { hexToProtobuf } from './protobufHelper';

let EnvelopeType = null;
let LocationUpdateType = null;

export async function loadEnvelopeProtobufSchema() {
  if (EnvelopeType && LocationUpdateType) {
    return { EnvelopeType, LocationUpdateType };
  }

  const protoDefinition = `
    syntax = "proto3";
    package tinyweb;

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

    message LocationUpdate {
      double lat = 1;
      double lon = 2;
      uint32 accuracy_m = 3;
      uint64 timestamp = 4;
      string location_name = 5;
    }
  `;

  const root = protobuf.parse(protoDefinition, { keepCase: true }).root;
  EnvelopeType = root.lookupType('tinyweb.Envelope');
  LocationUpdateType = root.lookupType('tinyweb.LocationUpdate');

  return { EnvelopeType, LocationUpdateType };
}

/**
 * Deserialize protobuf-encoded Envelope bytes to a JS object compatible with decryptPayload()
 * @param {Uint8Array|string} envelopeBytes - Protobuf-encoded envelope (Uint8Array or hex string)
 * @returns {Promise<Object>} { header, encryptedPayload, signature }
 */
export async function deserializeEnvelopeFromProtobuf(envelopeBytes) {
  const { EnvelopeType } = await loadEnvelopeProtobufSchema();

  let bytes = envelopeBytes;
  if (typeof envelopeBytes === 'string') {
    bytes = hexToProtobuf(envelopeBytes);
  }

  const env = EnvelopeType.decode(bytes);

  const header = {
    version: env.header.version,
    contentType: env.header.content_type,
    schemaVersion: env.header.schema_version,
    timestamp: Number(env.header.timestamp),
    senderPubkey: new Uint8Array(env.header.sender_pubkey),
    recipientsPubkey: (env.header.recipients_pubkey || []).map(pk => new Uint8Array(pk)),
    groupId: env.header.group_id && env.header.group_id.length > 0 ? new Uint8Array(env.header.group_id) : null,
  };

  const { EncryptedPayload } = await import('./encryption.js');
  const encryptedPayload = new EncryptedPayload();
  encryptedPayload.ciphertext = new Uint8Array(env.payload_ciphertext);
  encryptedPayload.nonce = new Uint8Array(env.payload_nonce);
  encryptedPayload.ephemeralPubkey = new Uint8Array(env.ephemeral_pubkey);
  encryptedPayload.numRecipients = header.recipientsPubkey.length;

  // Map keywraps by recipient pubkey (ed25519) hex
  const keywrapMap = new Map();
  for (const keywrap of (env.keywraps || [])) {
    const recipientKey = new Uint8Array(keywrap.recipient_pubkey);
    const keyHex = Array.from(recipientKey).map(b => b.toString(16).padStart(2, '0')).join('');
    keywrapMap.set(keyHex, keywrap);
  }

  encryptedPayload.encryptedKeys = [];
  encryptedPayload.keyNonces = [];
  for (const recipientPubkey of header.recipientsPubkey) {
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

  const signature = new Uint8Array(env.signature);

  return { header, encryptedPayload, signature };
}


