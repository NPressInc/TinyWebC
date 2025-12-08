/**
 * API client for connecting to TinyWeb docker nodes
 * Handles HTTP communication with running nodes
 */

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
 * Send an envelope to a node
 * @param {string} nodeUrl - Base URL of the node
 * @param {string} envelopeHex - Hex-encoded protobuf-serialized envelope
 * @returns {Promise<Object>} Response object
 */
export async function sendEnvelope(nodeUrl, envelopeHex) {
  try {
    const response = await fetch(`${nodeUrl}/gossip/envelope`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        envelope_hex: envelopeHex,
      }),
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || `HTTP ${response.status}`);
    }
    
    return data;
  } catch (error) {
    throw new Error(`Failed to send envelope to ${nodeUrl}: ${error.message}`);
  }
}

/**
 * Get messages between two users
 * @param {string} nodeUrl - Base URL of the node
 * @param {string} userPubkey - User's public key (hex)
 * @param {string} withPubkey - Other user's public key (hex)
 * @returns {Promise<Object>} Messages response (contains envelope_list_hex)
 */
export async function getMessages(nodeUrl, userPubkey, withPubkey) {
  try {
    const url = new URL(`${nodeUrl}/gossip/messages`);
    url.searchParams.append('user', userPubkey);
    url.searchParams.append('with', withPubkey);
    
    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    
    if (!response.ok) {
      throw new Error(`Failed to get messages: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    throw new Error(`Failed to get messages from ${nodeUrl}: ${error.message}`);
  }
}

/**
 * Get recent messages
 * @param {string} nodeUrl - Base URL of the node
 * @param {number} limit - Maximum number of messages to return (default: 50)
 * @returns {Promise<Object>} Recent messages response (contains envelope_list_hex)
 */
export async function getRecentMessages(nodeUrl, limit = 50) {
  try {
    const url = new URL(`${nodeUrl}/gossip/recent`);
    url.searchParams.append('limit', limit.toString());
    
    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    
    if (!response.ok) {
      throw new Error(`Failed to get recent messages: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    throw new Error(`Failed to get recent messages from ${nodeUrl}: ${error.message}`);
  }
}

/**
 * Get conversations for a user
 * @param {string} nodeUrl - Base URL of the node
 * @param {string} userPubkey - User's public key (hex)
 * @returns {Promise<Object>} Conversations response
 */
export async function getConversations(nodeUrl, userPubkey) {
  try {
    const url = new URL(`${nodeUrl}/gossip/conversations`);
    url.searchParams.append('user', userPubkey);
    
    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    
    if (!response.ok) {
      throw new Error(`Failed to get conversations: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    throw new Error(`Failed to get conversations from ${nodeUrl}: ${error.message}`);
  }
}

// Export default node URLs for convenience
export { DEFAULT_NODE_URLS };

