/**
 * Conversation ID utilities
 * Generates a deterministic conversation_id from participant public keys
 * This is a frontend-only concept to keep the backend simple
 */

import sodium from 'libsodium-wrappers';

/**
 * Sort two pubkeys in lexicographic order to ensure consistent conversation_id
 * regardless of which participant is "user" vs "partner"
 * @param {string} pubkey1 - First public key (hex)
 * @param {string} pubkey2 - Second public key (hex)
 * @returns {Array<string>} Sorted array [smaller, larger]
 */
function sortPubkeys(pubkey1, pubkey2) {
  // Compare as hex strings (case-insensitive)
  const p1 = pubkey1.toLowerCase();
  const p2 = pubkey2.toLowerCase();
  return p1 < p2 ? [pubkey1, pubkey2] : [pubkey2, pubkey1];
}

/**
 * Calculate conversation_id from participant public keys
 * Uses SHA256 hash of sorted participant pubkeys
 * @param {string} pubkey1 - First participant's public key (hex)
 * @param {string} pubkey2 - Second participant's public key (hex)
 * @returns {Promise<string>} Conversation ID (hex string)
 */
export async function calculateConversationId(pubkey1, pubkey2) {
  await sodium.ready;
  
  // Sort pubkeys to ensure consistent ID regardless of order
  const [p1, p2] = sortPubkeys(pubkey1, pubkey2);
  
  // Convert hex strings to bytes
  const p1Bytes = sodium.from_hex(p1);
  const p2Bytes = sodium.from_hex(p2);
  
  // Concatenate sorted pubkeys
  const combined = new Uint8Array(p1Bytes.length + p2Bytes.length);
  combined.set(p1Bytes, 0);
  combined.set(p2Bytes, p1Bytes.length);
  
  // Hash with SHA256
  const hash = sodium.crypto_hash_sha256(combined);
  
  // Return as hex string
  return sodium.to_hex(hash);
}

/**
 * Get conversation partner pubkey from a conversation
 * Given user's pubkey and conversation_id, returns the partner's pubkey
 * Note: This requires storing a mapping or deriving from messages
 * For now, we'll use this to identify conversations in the UI
 * @param {string} userPubkey - User's public key (hex)
 * @param {string} conversationId - Conversation ID (hex)
 * @returns {Promise<string|null>} Partner's public key or null if not found
 */
export async function getPartnerFromConversationId(userPubkey, conversationId) {
  // This is a placeholder - in practice, you'd need to store a mapping
  // or derive it from the messages themselves
  // For now, conversations are identified by partner pubkey directly
  return null;
}

/**
 * Get conversation ID from a message
 * Extracts sender and recipient(s) and calculates conversation_id
 * @param {Object} message - Decoded message object
 * @param {string} userPubkey - User's public key (hex)
 * @returns {Promise<string>} Conversation ID (hex string)
 */
export async function getConversationIdFromMessage(message, userPubkey) {
  await sodium.ready;
  
  const userPubkeyBytes = sodium.from_hex(userPubkey);
  
  // Determine partner pubkey
  let partnerPubkey = null;
  
  // Check if user is sender
  const senderHex = Array.from(message.header.senderPubkey)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  const isUserSender = sodium.memcmp(
    new Uint8Array(message.header.senderPubkey),
    userPubkeyBytes
  );
  
  if (isUserSender) {
    // User is sender, partner is first recipient
    if (message.header.recipientsPubkey && message.header.recipientsPubkey.length > 0) {
      partnerPubkey = Array.from(message.header.recipientsPubkey[0])
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    }
  } else {
    // User is recipient, partner is sender
    partnerPubkey = senderHex;
  }
  
  if (!partnerPubkey) {
    throw new Error('Could not determine conversation partner from message');
  }
  
  return calculateConversationId(userPubkey, partnerPubkey);
}

