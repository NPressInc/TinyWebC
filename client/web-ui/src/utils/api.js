/**
 * API client for connecting to TinyWeb docker nodes
 * Handles HTTP communication with running nodes
 */

import { addAuthHeaders } from './requestAuth.js';

// Default node URLs (with port mappings from docker-compose.test.yml)
const DEFAULT_NODE_URLS = {
  node_01: 'http://localhost:8001',
  node_02: 'http://localhost:8002',
  node_03: 'http://localhost:8003',
  node_04: 'http://localhost:8004',
};

/**
 * Detect which nodes are running by trying to connect to them
 * @returns {Promise<Array<string>>} Array of node URLs that are responding
 */
export async function detectRunningNodes() {
  const runningNodes = [];
  
  for (const [nodeId, url] of Object.entries(DEFAULT_NODE_URLS)) {
    try {
      const response = await fetch(`${url}/health`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
        mode: 'cors', // Explicitly enable CORS
      });
      
      if (response.ok) {
        runningNodes.push({ nodeId, url });
        console.log(`✓ ${nodeId} is running at ${url}`);
      } else {
        console.log(`✗ ${nodeId} returned status ${response.status}`);
      }
    } catch (error) {
      console.error(`✗ ${nodeId} not responding:`, error);
      // Log more details for debugging
      if (error.message) {
        console.error(`  Error message: ${error.message}`);
      }
      if (error.stack) {
        console.error(`  Stack: ${error.stack}`);
      }
    }
  }
  
  console.log(`Detected ${runningNodes.length} running node(s):`, runningNodes);
  return runningNodes;
}

/**
 * Get health status of a node
 * @param {string} nodeUrl - Base URL of the node (e.g., 'http://localhost:8001')
 * @returns {Promise<Object>} Health status object
 */
export async function getNodeHealth(nodeUrl) {
  try {
    const response = await fetch(`${nodeUrl}/health`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    
    if (!response.ok) {
      throw new Error(`Health check failed: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    throw new Error(`Failed to get health from ${nodeUrl}: ${error.message}`);
  }
}

/**
 * Get list of peers from a node
 * @param {string} nodeUrl - Base URL of the node
 * @returns {Promise<Object>} Peers object with count and peer list
 */
export async function getPeers(nodeUrl) {
  try {
    const response = await fetch(`${nodeUrl}/gossip/peers`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    
    if (!response.ok) {
      throw new Error(`Failed to get peers: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    throw new Error(`Failed to get peers from ${nodeUrl}: ${error.message}`);
  }
}

/**
 * Send a user message to a node
 * @param {string} nodeUrl - Base URL of the node
 * @param {Object} message - JavaScript Message object (from createSignedMessage)
 * @returns {Promise<Object>} Response object with status
 */
export async function sendMessage(nodeUrl, message) {
  try {
    // Serialize message to binary protobuf
    const { serializeMessageToProtobuf } = await import('./messageHelper.js');
    const messageBytes = await serializeMessageToProtobuf(message);
    
    const url = `${nodeUrl}/messages/submit`;
    
    // Add authentication headers
    const fetchOptions = await addAuthHeaders('POST', url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-protobuf',
        'Content-Length': messageBytes.length.toString(), // Explicitly set Content-Length
      },
      body: messageBytes,
    });
    
    const response = await fetch(url, fetchOptions);
    
    // Backend returns JSON response (not binary)
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || `HTTP ${response.status}`);
    }
    
    return data;
  } catch (error) {
    throw new Error(`Failed to send message to ${nodeUrl}: ${error.message}`);
  }
}

/**
 * Get messages between two users
 * @param {string} nodeUrl - Base URL of the node
 * @param {string} userPubkey - User's public key (hex)
 * @param {string} withPubkey - Other user's public key (hex)
 * @returns {Promise<Array>} Array of Message objects
 */
export async function getMessages(nodeUrl, userPubkey, withPubkey) {
  try {
    const url = new URL(`${nodeUrl}/messages/conversation`);
    url.searchParams.append('user', userPubkey);
    url.searchParams.append('with', withPubkey);
    
    // Add authentication headers
    const fetchOptions = await addAuthHeaders('GET', url.toString(), {
      method: 'GET',
      headers: { 'Accept': 'application/x-protobuf' },
    });
    
    const response = await fetch(url.toString(), fetchOptions);
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error('[getMessages] Error response:', response.status, errorText);
      let errorMsg = `Failed to get messages: ${response.status}`;
      try {
        const errorJson = JSON.parse(errorText);
        errorMsg = errorJson.error || errorMsg;
      } catch (e) {
        errorMsg = errorText || errorMsg;
      }
      throw new Error(errorMsg);
    }
    
    // Check Content-Type header
    const contentType = response.headers.get('Content-Type');
    if (!contentType || !contentType.includes('application/x-protobuf')) {
      throw new Error(`Unexpected Content-Type: ${contentType}, expected application/x-protobuf`);
    }
    
    // Get binary response
    const arrayBuffer = await response.arrayBuffer();
    const messageBytes = new Uint8Array(arrayBuffer);
    
    // Deserialize MessageList
    const { deserializeMessageListFromProtobuf } = await import('./messageHelper.js');
    const messages = await deserializeMessageListFromProtobuf(messageBytes);
    
    return messages;
  } catch (error) {
    throw new Error(`Failed to get messages from ${nodeUrl}: ${error.message}`);
  }
}

/**
 * Get recent messages for a user
 * @param {string} nodeUrl - Base URL of the node
 * @param {string} userPubkey - User's public key (hex)
 * @param {number} limit - Maximum number of messages to return (default: 50)
 * @returns {Promise<Array>} Array of Message objects
 */
export async function getRecentMessages(nodeUrl, userPubkey, limit = 50) {
  try {
    const url = new URL(`${nodeUrl}/messages/recent`);
    url.searchParams.append('user', userPubkey);
    url.searchParams.append('limit', limit.toString());
    
    // Add authentication headers
    const fetchOptions = await addAuthHeaders('GET', url.toString(), {
      method: 'GET',
      headers: { 'Accept': 'application/x-protobuf' },
    });
    
    const response = await fetch(url.toString(), fetchOptions);
    
    if (!response.ok) {
      let errorMsg = `Failed to get recent messages: ${response.status}`;
      try {
        const errorText = await response.text();
        console.error('[getRecentMessages] Error response:', response.status, errorText);
        try {
          const errorJson = JSON.parse(errorText);
          errorMsg = errorJson.error || errorMsg;
        } catch (e) {
          errorMsg = errorText || errorMsg;
        }
      } catch (e) {
        // Ignore
      }
      throw new Error(errorMsg);
    }
    
    // Check Content-Type header
    const contentType = response.headers.get('Content-Type');
    if (!contentType || !contentType.includes('application/x-protobuf')) {
      throw new Error(`Unexpected Content-Type: ${contentType}, expected application/x-protobuf`);
    }
    
    // Get binary response
    const arrayBuffer = await response.arrayBuffer();
    const messageBytes = new Uint8Array(arrayBuffer);
    
    // Deserialize MessageList
    const { deserializeMessageListFromProtobuf } = await import('./messageHelper.js');
    const messages = await deserializeMessageListFromProtobuf(messageBytes);
    
    return messages;
  } catch (error) {
    throw new Error(`Failed to get recent messages from ${nodeUrl}: ${error.message}`);
  }
}

/**
 * Get conversations for a user
 * @param {string} nodeUrl - Base URL of the node
 * @param {string} userPubkey - User's public key (hex)
 * @returns {Promise<Array>} Array of ConversationSummary objects
 */
export async function getConversations(nodeUrl, userPubkey) {
  try {
    const url = new URL(`${nodeUrl}/messages/conversations`);
    url.searchParams.append('user', userPubkey);
    
    // Add authentication headers
    const fetchOptions = await addAuthHeaders('GET', url.toString(), {
      method: 'GET',
      headers: { 'Accept': 'application/x-protobuf' },
    });
    
    const response = await fetch(url.toString(), fetchOptions);
    
    if (!response.ok) {
      throw new Error(`Failed to get conversations: ${response.status}`);
    }
    
    // Check Content-Type header
    const contentType = response.headers.get('Content-Type');
    if (!contentType || !contentType.includes('application/x-protobuf')) {
      throw new Error(`Unexpected Content-Type: ${contentType}, expected application/x-protobuf`);
    }
    
    // Get binary response
    const arrayBuffer = await response.arrayBuffer();
    const conversationListBytes = new Uint8Array(arrayBuffer);
    
    // Deserialize ConversationList using existing protobufDecode
    const { decodeConversationList } = await import('./protobufDecode.js');
    // decodeConversationList expects hex, so convert
    const hex = Array.from(conversationListBytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    const conversations = await decodeConversationList(hex);
    
    return conversations;
  } catch (error) {
    throw new Error(`Failed to get conversations from ${nodeUrl}: ${error.message}`);
  }
}

/**
 * Get all users in the network
 * @param {string} nodeUrl - Base URL of the node
 * @returns {Promise<Object>} Users response with array of users
 */
export async function getUsers(nodeUrl) {
  try {
    const url = `${nodeUrl}/users`;
    
    // Add authentication headers
    const fetchOptions = await addAuthHeaders('GET', url, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    
    const response = await fetch(url, fetchOptions);
    
    if (!response.ok) {
      throw new Error(`Failed to get users: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    throw new Error(`Failed to get users from ${nodeUrl}: ${error.message}`);
  }
}

// Export default node URLs for convenience
export { DEFAULT_NODE_URLS };

