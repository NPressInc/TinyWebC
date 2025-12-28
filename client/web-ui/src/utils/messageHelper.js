/**
 * Protobuf serialization helper for Messages
 * Uses protobufjs to serialize JavaScript Message objects to protobuf binary format
 */

import protobuf from 'protobufjs';
import { hexToProtobuf, protobufToHex } from './protobufHelper';

let MessageType = null;
let MessageHeaderType = null;
let MessageRecipientKeyWrapType = null;
let MessageListType = null;

/**
 * Load protobuf schema for Messages (lazy loading, cached)
 * @returns {Promise<Object>} Object with MessageType, MessageHeaderType, MessageRecipientKeyWrapType, MessageListType
 */
export async function loadMessageProtobufSchema() {
  if (MessageType && MessageHeaderType && MessageRecipientKeyWrapType && MessageListType) {
    return { MessageType, MessageHeaderType, MessageRecipientKeyWrapType, MessageListType };
  }

  try {
    // Define schema inline (more reliable than loading from file in browser)
    const protoDefinition = `
      syntax = "proto3";
      package tinyweb;
      
      message MessageHeader {
        uint32 version = 1;
        uint64 timestamp = 2;
        bytes sender_pubkey = 3;
        repeated bytes recipients_pubkey = 4;
        bytes group_id = 5;
      }
      
      message MessageRecipientKeyWrap {
        bytes recipient_pubkey = 1;
        bytes key_nonce = 2;
        bytes wrapped_key = 3;
      }
      
      message Message {
        MessageHeader header = 1;
        bytes payload_nonce = 2;
        bytes ephemeral_pubkey = 3;
        bytes payload_ciphertext = 4;
        repeated MessageRecipientKeyWrap keywraps = 5;
        bytes signature = 6;
      }
      
      message MessageList {
        repeated Message messages = 1;
        uint32 total_count = 2;
      }
    `;
    
    const root = protobuf.parse(protoDefinition, { keepCase: true }).root;
    
    MessageType = root.lookupType('tinyweb.Message');
    MessageHeaderType = root.lookupType('tinyweb.MessageHeader');
    MessageRecipientKeyWrapType = root.lookupType('tinyweb.MessageRecipientKeyWrap');
    MessageListType = root.lookupType('tinyweb.MessageList');
    
    if (!MessageType || !MessageHeaderType || !MessageRecipientKeyWrapType || !MessageListType) {
      throw new Error('Failed to load Message protobuf types');
    }
    
    return { MessageType, MessageHeaderType, MessageRecipientKeyWrapType, MessageListType };
  } catch (error) {
    throw new Error(`Failed to load Message protobuf schema: ${error.message}`);
  }
}

/**
 * Serialize a JavaScript Message object to protobuf binary format
 * @param {Object} message - JavaScript Message object from createSignedMessage()
 * @returns {Promise<Uint8Array>} Protobuf-serialized message as binary
 */
export async function serializeMessageToProtobuf(message) {
  const { MessageType, MessageHeaderType, MessageRecipientKeyWrapType } = await loadMessageProtobufSchema();
  
  // Create MessageHeader
  const header = {
    version: message.header.version,
    timestamp: message.header.timestamp, // Already in seconds (UNIX epoch)
    sender_pubkey: message.header.senderPubkey instanceof Uint8Array 
      ? message.header.senderPubkey 
      : new Uint8Array(message.header.senderPubkey),
    recipients_pubkey: message.header.recipientsPubkey.map(pk => 
      pk instanceof Uint8Array ? pk : new Uint8Array(pk)
    ),
    group_id: message.header.groupId 
      ? (message.header.groupId instanceof Uint8Array ? message.header.groupId : new Uint8Array(message.header.groupId))
      : new Uint8Array(0),
  };
  
  // Validate and create header message
  const headerMessage = MessageHeaderType.create(header);
  const headerError = MessageHeaderType.verify(headerMessage);
  if (headerError) {
    throw new Error(`Invalid message header: ${headerError}`);
  }
  
  // Create MessageRecipientKeyWrap messages
  // Map encryptedPayload structure to keywraps
  const keywraps = [];
  const encryptedPayload = message.encryptedPayload;
  
  if (encryptedPayload.encryptedKeys && encryptedPayload.keyNonces && message.header.recipientsPubkey) {
    for (let i = 0; i < message.header.recipientsPubkey.length; i++) {
      const recipientPubkey = message.header.recipientsPubkey[i];
      const keyNonce = encryptedPayload.keyNonces[i];
      const wrappedKey = encryptedPayload.encryptedKeys[i];
      
      const keywrap = {
        recipient_pubkey: recipientPubkey instanceof Uint8Array ? recipientPubkey : new Uint8Array(recipientPubkey),
        key_nonce: keyNonce instanceof Uint8Array ? keyNonce : new Uint8Array(keyNonce),
        wrapped_key: wrappedKey instanceof Uint8Array ? wrappedKey : new Uint8Array(wrappedKey),
      };
      
      const keywrapMessage = MessageRecipientKeyWrapType.create(keywrap);
      const keywrapError = MessageRecipientKeyWrapType.verify(keywrapMessage);
      if (keywrapError) {
        throw new Error(`Invalid keywrap ${i}: ${keywrapError}`);
      }
      
      keywraps.push(keywrapMessage);
    }
  }
  
  // Create Message message
  const messageProto = {
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
    signature: message.signature instanceof Uint8Array
      ? message.signature
      : new Uint8Array(message.signature),
  };
  
  // Validate message
  const messageError = MessageType.verify(messageProto);
  if (messageError) {
    throw new Error(`Invalid message: ${messageError}`);
  }
  
  // Encode to binary
  const messageObj = MessageType.create(messageProto);
  const buffer = MessageType.encode(messageObj).finish();
  
  return new Uint8Array(buffer);
}

/**
 * Serialize message to protobuf and convert to hex string
 * @param {Object} message - JavaScript Message object
 * @returns {Promise<string>} Hex-encoded protobuf-serialized message
 */
export async function serializeMessageToProtobufHex(message) {
  const protobufBytes = await serializeMessageToProtobuf(message);
  return protobufToHex(protobufBytes);
}

/**
 * Deserialize protobuf-encoded message bytes to JavaScript object
 * @param {Uint8Array|string} messageBytes - Protobuf-encoded message (Uint8Array or hex string)
 * @returns {Promise<Object>} Decoded message object with header, encryptedPayload, and signature
 */
export async function deserializeMessageFromProtobuf(messageBytes) {
  const { MessageType } = await loadMessageProtobufSchema();
  
  // Convert hex string to Uint8Array if needed
  let bytes = messageBytes;
  if (typeof messageBytes === 'string') {
    bytes = hexToProtobuf(messageBytes);
  }
  
  // Decode protobuf message
  const message = MessageType.decode(bytes);
  
  // Extract header
  const header = {
    version: message.header.version,
    timestamp: Number(message.header.timestamp) * 1000, // Convert seconds to ms
    senderPubkey: new Uint8Array(message.header.sender_pubkey),
    recipientsPubkey: (message.header.recipients_pubkey || []).map(pk => new Uint8Array(pk)),
    groupId: message.header.group_id && message.header.group_id.length > 0 
      ? new Uint8Array(message.header.group_id) 
      : null,
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
  encryptedPayload.numRecipients = header.recipientsPubkey.length;
  
  // Create a map of recipient pubkey to keywrap using a more robust key comparison
  const keywrapMap = new Map();
  for (const keywrap of (message.keywraps || [])) {
    const recipientKey = new Uint8Array(keywrap.recipient_pubkey);
    // Use hex string as key for reliable comparison
    const keyHex = Array.from(recipientKey).map(b => b.toString(16).padStart(2, '0')).join('');
    keywrapMap.set(keyHex, keywrap);
  }
  
  // Match keywraps to recipientPubkeys in order
  // This ensures encryptedKeys array matches the order of recipientsPubkey array
  for (const recipientPubkey of header.recipientsPubkey) {
    const recipientKey = recipientPubkey instanceof Uint8Array ? recipientPubkey : new Uint8Array(recipientPubkey);
    const keyHex = Array.from(recipientKey).map(b => b.toString(16).padStart(2, '0')).join('');
    const keywrap = keywrapMap.get(keyHex);
    if (keywrap) {
      encryptedPayload.encryptedKeys.push(new Uint8Array(keywrap.wrapped_key));
      encryptedPayload.keyNonces.push(new Uint8Array(keywrap.key_nonce));
    } else {
      // Log warning but don't throw - might be missing keywrap for sender if message was sent before fix
      console.warn(`Keywrap not found for recipient pubkey: ${keyHex}`);
      // Still add placeholder to maintain array alignment (will fail decryption but won't crash)
      encryptedPayload.encryptedKeys.push(new Uint8Array(0));
      encryptedPayload.keyNonces.push(new Uint8Array(0));
    }
  }
  
  // Verify we have the same number of encrypted keys as recipients
  if (encryptedPayload.encryptedKeys.length !== header.recipientsPubkey.length) {
    throw new Error(`Mismatch: ${encryptedPayload.encryptedKeys.length} encrypted keys for ${header.recipientsPubkey.length} recipients`);
  }
  
  // Extract signature
  const signature = new Uint8Array(message.signature);
  
  return {
    header,
    encryptedPayload,
    signature,
  };
}

/**
 * Serialize an array of Message objects to MessageList protobuf binary format
 * @param {Array<Object>} messages - Array of JavaScript Message objects
 * @returns {Promise<Uint8Array>} Protobuf-serialized MessageList as binary
 */
export async function serializeMessageListToProtobuf(messages) {
  const { MessageListType } = await loadMessageProtobufSchema();
  
  // Serialize each message
  const serializedMessages = [];
  for (const message of messages) {
    const messageBytes = await serializeMessageToProtobuf(message);
    // Decode back to protobuf object for MessageList
    const { MessageType } = await loadMessageProtobufSchema();
    const messageObj = MessageType.decode(messageBytes);
    serializedMessages.push(messageObj);
  }
  
  // Create MessageList
  const messageList = {
    messages: serializedMessages,
    total_count: messages.length,
  };
  
  // Validate
  const listError = MessageListType.verify(messageList);
  if (listError) {
    throw new Error(`Invalid message list: ${listError}`);
  }
  
  // Encode to binary
  const listObj = MessageListType.create(messageList);
  const buffer = MessageListType.encode(listObj).finish();
  
  return new Uint8Array(buffer);
}

/**
 * Deserialize binary MessageList protobuf to array of Message objects
 * @param {Uint8Array|string} messageListBytes - Protobuf-encoded MessageList (Uint8Array or hex string)
 * @returns {Promise<Array<Object>>} Array of decoded Message objects
 */
export async function deserializeMessageListFromProtobuf(messageListBytes) {
  const { MessageListType } = await loadMessageProtobufSchema();
  
  // Convert hex string to Uint8Array if needed
  let bytes = messageListBytes;
  if (typeof messageListBytes === 'string') {
    bytes = hexToProtobuf(messageListBytes);
  }
  
  // Decode protobuf MessageList
  const messageList = MessageListType.decode(bytes);
  
  // Deserialize each message
  const messages = [];
  if (messageList.messages && messageList.messages.length > 0) {
    for (const messageProto of messageList.messages) {
      // Re-encode the message to binary, then deserialize using our helper
      const { MessageType } = await loadMessageProtobufSchema();
      const messageBytes = MessageType.encode(messageProto).finish();
      const message = await deserializeMessageFromProtobuf(new Uint8Array(messageBytes));
      messages.push(message);
    }
  }
  
  return messages;
}

