/**
 * API client for connecting to TinyWeb docker nodes
 * Handles HTTP communication with running nodes
 */

import { addAuthHeaders } from './requestAuth.js';
import sodium from 'libsodium-wrappers';
import { decryptPayload } from './encryption.js';
import { deserializeClientRequestFromProtobuf, loadClientRequestProtobufSchema } from './clientRequestHelper.js';
import { deserializeEnvelopeFromProtobuf } from './envelopeHelper.js';

// Get backend host from environment variable or default to localhost
// For SSH/remote scenarios, set REACT_APP_BACKEND_HOST to the remote server's IP/hostname
// Example: REACT_APP_BACKEND_HOST=192.168.1.100
const BACKEND_HOST = process.env.REACT_APP_BACKEND_HOST || 'localhost';

// Default node URLs (with port mappings from docker-compose.test.yml)
const DEFAULT_NODE_URLS = {
  node_01: `http://${BACKEND_HOST}:8001`,
  node_02: `http://${BACKEND_HOST}:8002`,
  node_03: `http://${BACKEND_HOST}:8003`,
  node_04: `http://${BACKEND_HOST}:8004`,
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
 * Login to the node (verify key and authenticate)
 * @param {string} nodeUrl - Base URL of the node
 * @returns {Promise<Object>} Login response with pubkey
 */
export async function login(nodeUrl) {
  try {
    // Ensure nodeUrl doesn't have trailing slash
    const cleanNodeUrl = nodeUrl.replace(/\/$/, '');
    const url = `${cleanNodeUrl}/auth/login`;
    console.log('[login] Attempting to login to:', url);
    console.log('[login] Node URL:', nodeUrl, '-> Clean:', cleanNodeUrl);
    
    // Test connection first with a simple OPTIONS request
    try {
      const testResponse = await fetch(url, {
        method: 'OPTIONS',
        headers: {
          'Origin': window.location.origin,
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'content-type,x-user-pubkey,x-signature,x-timestamp'
        }
      });
      console.log('[login] Preflight test response:', testResponse.status, testResponse.statusText);
    } catch (preflightError) {
      console.error('[login] Preflight test failed:', preflightError);
      throw new Error(`Cannot connect to backend at ${url}: ${preflightError.message}`);
    }
    
    // Add authentication headers (signed request)
    const fetchOptions = await addAuthHeaders('POST', url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({}), // Empty body, auth is via headers
    });
    
    console.log('[login] Fetch options:', {
      method: fetchOptions.method,
      url: url,
      hasHeaders: !!fetchOptions.headers
    });
    
    const response = await fetch(url, fetchOptions);
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || `Login failed: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    throw new Error(`Failed to login to ${nodeUrl}: ${error.message}`);
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

/**
 * Submit a location update
 * @param {string} nodeUrl - Base URL of the node
 * @param {Object} clientRequest - JavaScript ClientRequest object (from createSignedClientRequest)
 * @returns {Promise<Object>} Response object with status
 */
export async function submitLocation(nodeUrl, clientRequest) {
  try {
    // Serialize ClientRequest to binary protobuf
    const { serializeClientRequestToProtobuf } = await import('./clientRequestHelper.js');
    const requestBytes = await serializeClientRequestToProtobuf(clientRequest);
    
    const url = `${nodeUrl}/location/update`;
    
    // Add authentication headers
    const fetchOptions = await addAuthHeaders('POST', url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-protobuf',
        'Content-Length': requestBytes.length.toString(),
      },
      body: requestBytes,
    });
    
    const response = await fetch(url, fetchOptions);
    
    // Backend returns JSON response
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || `HTTP ${response.status}`);
    }
    
    return data;
  } catch (error) {
    throw new Error(`Failed to submit location to ${nodeUrl}: ${error.message}`);
  }
}

/**
 * Get the latest location for a user
 * @param {string} nodeUrl - Base URL of the node
 * @param {string} userPubkey - User's public key (hex)
 * @returns {Promise<Object>} LocationUpdate object with lat, lon, accuracy_m, timestamp, location_name
 */
export async function getLocation(nodeUrl, userPubkey) {
  try {
    const url = `${nodeUrl}/location/${userPubkey}`;
    
    // Add authentication headers
    const fetchOptions = await addAuthHeaders('GET', url, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    
    const response = await fetch(url, fetchOptions);
    
    if (!response.ok) {
      let errorMsg = `Failed to get location: ${response.status}`;
      try {
        const errorText = await response.text();
        const errorJson = JSON.parse(errorText);
        errorMsg = errorJson.error || errorMsg;
      } catch (e) {
        // Ignore
      }
      throw new Error(errorMsg);
    }
    
    const data = await response.json();
    if (!data || !data.data_hex) {
      throw new Error('Invalid response (missing data_hex)');
    }

    await sodium.ready;
    const bytes = sodium.from_hex(data.data_hex);

    // Decode encrypted record
    const decoded = data.is_envelope
      ? await deserializeEnvelopeFromProtobuf(bytes)
      : await deserializeClientRequestFromProtobuf(bytes);

    // Convert recipients (Ed25519) -> X25519 for decryptPayload()
    const recipientsX25519 = decoded.header.recipientsPubkey
      ? decoded.header.recipientsPubkey.map(pk => sodium.crypto_sign_ed25519_pk_to_curve25519(pk))
      : decoded.header.recipients_pubkey.map(pk => sodium.crypto_sign_ed25519_pk_to_curve25519(pk));

    const decryptedBytes = await decryptPayload(decoded.encryptedPayload, recipientsX25519);

    // Decode LocationUpdate
    const { LocationUpdateType } = await loadClientRequestProtobufSchema();
    const loc = LocationUpdateType.decode(decryptedBytes);

    return {
      lat: loc.lat,
      lon: loc.lon,
      accuracy_m: loc.accuracy_m,
      timestamp: Number(loc.timestamp),
      location_name: loc.location_name || '',
    };
  } catch (error) {
    throw new Error(`Failed to get location from ${nodeUrl}: ${error.message}`);
  }
}

/**
 * Get location history for a user
 * @param {string} nodeUrl - Base URL of the node
 * @param {string} userPubkey - User's public key (hex)
 * @param {number} limit - Maximum number of locations to return (default: 50)
 * @param {number} offset - Number of locations to skip (default: 0)
 * @returns {Promise<Array>} Array of LocationUpdate objects
 */
export async function getLocationHistory(nodeUrl, userPubkey, limit = 50, offset = 0) {
  try {
    const url = new URL(`${nodeUrl}/location/history/${userPubkey}`);
    url.searchParams.append('limit', limit.toString());
    url.searchParams.append('offset', offset.toString());
    
    // Add authentication headers
    const fetchOptions = await addAuthHeaders('GET', url.toString(), {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    
    const response = await fetch(url.toString(), fetchOptions);
    
    if (!response.ok) {
      let errorMsg = `Failed to get location history: ${response.status}`;
      try {
        const errorText = await response.text();
        const errorJson = JSON.parse(errorText);
        errorMsg = errorJson.error || errorMsg;
      } catch (e) {
        // Ignore
      }
      throw new Error(errorMsg);
    }
    
    const data = await response.json();
    const updates = data.updates || [];
    if (!Array.isArray(updates)) return [];

    await sodium.ready;
    const { LocationUpdateType } = await loadClientRequestProtobufSchema();

    const out = [];
    for (const upd of updates) {
      if (!upd || !upd.data_hex) continue;
      try {
        const bytes = sodium.from_hex(upd.data_hex);
        const decoded = upd.is_envelope
          ? await deserializeEnvelopeFromProtobuf(bytes)
          : await deserializeClientRequestFromProtobuf(bytes);

        const recipientsEd = decoded.header.recipientsPubkey || decoded.header.recipients_pubkey || [];
        const recipientsX25519 = recipientsEd.map(pk => sodium.crypto_sign_ed25519_pk_to_curve25519(pk));

        const decryptedBytes = await decryptPayload(decoded.encryptedPayload, recipientsX25519);
        const loc = LocationUpdateType.decode(decryptedBytes);

        out.push({
          lat: loc.lat,
          lon: loc.lon,
          accuracy_m: loc.accuracy_m,
          timestamp: Number(loc.timestamp),
          location_name: loc.location_name || '',
        });
      } catch (e) {
        // If we can't decrypt one entry, skip it (still return the rest)
        console.warn('[getLocationHistory] Failed to decrypt one entry:', e);
      }
    }

    return out;
  } catch (error) {
    throw new Error(`Failed to get location history from ${nodeUrl}: ${error.message}`);
  }
}

// Export default node URLs for convenience
export { DEFAULT_NODE_URLS };

