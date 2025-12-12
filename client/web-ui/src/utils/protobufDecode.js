/**
 * Protobuf decoding utilities for API responses
 * Decodes hex-encoded protobuf messages from the backend
 */

import protobuf from 'protobufjs';
import { hexToProtobuf } from './protobufHelper';

let ConversationListType = null;
let EnvelopeListType = null;
let StoredEnvelopeType = null;

/**
 * Load protobuf schema for API responses (lazy loading, cached)
 */
async function loadApiProtobufSchema() {
  if (ConversationListType && EnvelopeListType) {
    return { ConversationListType, EnvelopeListType, StoredEnvelopeType };
  }

  try {
    const protoDefinition = `
      syntax = "proto3";
      package tinyweb;
      
      message ConversationSummary {
        bytes partner_pubkey = 1;
        uint64 last_message_timestamp = 2;
        uint32 unread_count = 3;
        bytes last_message_preview = 4;
      }
      
      message ConversationList {
        repeated ConversationSummary conversations = 1;
        uint32 total_count = 2;
      }
      
      message StoredEnvelope {
        uint64 id = 1;
        uint32 version = 2;
        uint32 content_type = 3;
        uint32 schema_version = 4;
        uint64 timestamp = 5;
        bytes sender = 6;
        bytes envelope = 7;
        uint64 expires_at = 8;
      }
      
      message EnvelopeList {
        repeated StoredEnvelope envelopes = 1;
        uint32 total_count = 2;
      }
    `;
    
    const root = protobuf.parse(protoDefinition, { keepCase: true }).root;
    
    ConversationListType = root.lookupType('tinyweb.ConversationList');
    EnvelopeListType = root.lookupType('tinyweb.EnvelopeList');
    StoredEnvelopeType = root.lookupType('tinyweb.StoredEnvelope');
    
    if (!ConversationListType || !EnvelopeListType || !StoredEnvelopeType) {
      throw new Error('Failed to load API protobuf types');
    }
    
    return { ConversationListType, EnvelopeListType, StoredEnvelopeType };
  } catch (error) {
    throw new Error(`Failed to load API protobuf schema: ${error.message}`);
  }
}

/**
 * Decode conversation_list_hex from API response
 * @param {string} hex - Hex-encoded protobuf ConversationList
 * @returns {Promise<Array>} Array of conversation objects
 */
export async function decodeConversationList(hex) {
  const { ConversationListType } = await loadApiProtobufSchema();
  
  const bytes = hexToProtobuf(hex);
  const message = ConversationListType.decode(bytes);
  
  const conversations = [];
  if (message.conversations && message.conversations.length > 0) {
    for (const conv of message.conversations) {
      conversations.push({
        partnerPubkey: Array.from(conv.partner_pubkey || []),
        partnerPubkeyHex: Array.from(conv.partner_pubkey || [])
          .map(b => b.toString(16).padStart(2, '0'))
          .join(''),
        lastMessageTimestamp: Number(conv.last_message_timestamp) * 1000, // Convert seconds to ms
        unreadCount: conv.unread_count || 0,
        lastMessagePreview: conv.last_message_preview ? Array.from(conv.last_message_preview) : null,
      });
    }
  }
  
  return conversations;
}

/**
 * Decode envelope_list_hex from API response
 * @param {string} hex - Hex-encoded protobuf EnvelopeList
 * @returns {Promise<Array>} Array of stored envelope objects
 */
export async function decodeEnvelopeList(hex) {
  const { EnvelopeListType } = await loadApiProtobufSchema();
  
  const bytes = hexToProtobuf(hex);
  const message = EnvelopeListType.decode(bytes);
  
  const envelopes = [];
  if (message.envelopes && message.envelopes.length > 0) {
    for (const stored of message.envelopes) {
      envelopes.push({
        id: Number(stored.id),
        version: stored.version,
        contentType: stored.content_type,
        schemaVersion: stored.schema_version,
        timestamp: Number(stored.timestamp) * 1000, // Convert seconds to ms
        sender: Array.from(stored.sender || []),
        senderHex: Array.from(stored.sender || [])
          .map(b => b.toString(16).padStart(2, '0'))
          .join(''),
        envelope: stored.envelope ? Array.from(stored.envelope) : null,
        expiresAt: Number(stored.expires_at) * 1000, // Convert seconds to ms
      });
    }
  }
  
  return envelopes;
}


