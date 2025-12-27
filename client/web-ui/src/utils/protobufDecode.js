/**
 * Protobuf decoding utilities for API responses
 * Decodes binary protobuf messages from the backend
 */

import { hexToProtobuf } from './protobufHelper';

let ConversationListType = null;

/**
 * Load protobuf schema for ConversationList (lazy loading, cached)
 */
async function loadConversationListSchema() {
  if (ConversationListType) {
    return { ConversationListType };
  }

  try {
    const protobuf = await import('protobufjs');
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
    `;
    
    const root = protobuf.parse(protoDefinition, { keepCase: true }).root;
    
    ConversationListType = root.lookupType('tinyweb.ConversationList');
    
    if (!ConversationListType) {
      throw new Error('Failed to load ConversationList protobuf type');
    }
    
    return { ConversationListType };
  } catch (error) {
    throw new Error(`Failed to load ConversationList protobuf schema: ${error.message}`);
  }
}

/**
 * Decode ConversationList from API response
 * @param {string} hex - Hex-encoded protobuf ConversationList
 * @returns {Promise<Array>} Array of conversation objects
 */
export async function decodeConversationList(hex) {
  const { ConversationListType } = await loadConversationListSchema();
  
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
 * Decode MessageList from API response
 * @param {Uint8Array|string} messageListBytes - Binary MessageList protobuf (Uint8Array or hex string)
 * @returns {Promise<Array>} Array of Message objects
 */
export async function decodeMessageList(messageListBytes) {
  // Use the messageHelper function
  const { deserializeMessageListFromProtobuf } = await import('./messageHelper.js');
  return deserializeMessageListFromProtobuf(messageListBytes);
}




