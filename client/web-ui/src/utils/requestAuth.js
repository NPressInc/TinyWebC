import sodium from 'libsodium-wrappers';
import keyStore from './keystore.js';

/**
 * Request authentication utility
 * Signs HTTP requests to authenticate the requester
 */

// Ensure sodium is ready
async function ensureSodiumReady() {
  await sodium.ready;
}

/**
 * Compute request signing digest
 * Signs: method + uri + query + timestamp + pubkey
 * Matches backend: request_auth.c::compute_request_digest
 * @param {string} method - HTTP method (e.g., "GET", "POST")
 * @param {string} uri - URI path (e.g., "/messages/recent")
 * @param {string} query - Query string (e.g., "?user=abc&limit=50" or "")
 * @param {string} timestamp - Unix timestamp as string
 * @param {Uint8Array} pubkey - 32-byte Ed25519 public key
 * @returns {Promise<Uint8Array>} - SHA256 digest (32 bytes)
 */
async function computeRequestDigest(method, uri, query, timestamp, pubkey) {
  await ensureSodiumReady();
  
  // Domain separator (matches backend: "TWREQUEST\0")
  const domain = new Uint8Array([84, 87, 82, 69, 81, 85, 69, 83, 84, 0]); // "TWREQUEST\0"
  
  // Build parts array to match backend incremental hashing exactly
  // Backend does: domain, method, uri, query (if len > 0), timestamp, pubkey
  const parts = [];
  parts.push(domain);
  parts.push(new TextEncoder().encode(method));
  parts.push(new TextEncoder().encode(uri));
  // Only add query if it's non-empty (matches backend: if (hm->query.len > 0))
  if (query && query.length > 0) {
    parts.push(new TextEncoder().encode(query));
  }
  parts.push(new TextEncoder().encode(timestamp));
  parts.push(pubkey);
  
  // Combine all parts (this matches the backend's incremental SHA256_Update calls)
  const totalLength = parts.reduce((sum, part) => sum + part.length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    combined.set(part, offset);
    offset += part.length;
  }
  
  // Hash the combined data (single SHA256 of concatenated data = same as incremental updates)
  const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
  return new Uint8Array(hashBuffer);
}

/**
 * Sign an HTTP request
 * @param {string} method - HTTP method
 * @param {string} uri - URI path
 * @param {string} query - Query string (including "?" if present)
 * @returns {Promise<Object>} Object with headers: { X-User-Pubkey, X-Signature, X-Timestamp }
 */
export async function signRequest(method, uri, query = '') {
  await ensureSodiumReady();
  await keyStore.init();
  
  if (!keyStore.isKeypairLoaded()) {
    throw new Error('No keypair loaded. Please load or generate keys first.');
  }
  
  // Get user's public key
  const pubkey = keyStore.getPublicKey();
  const pubkeyHex = sodium.to_hex(pubkey);
  
  // Generate timestamp (Unix seconds)
  const timestamp = Math.floor(Date.now() / 1000).toString();
  
  // Compute digest
  const digest = await computeRequestDigest(method, uri, query, timestamp, pubkey);
  
  // Sign digest
  const privateKey = keyStore._getPrivateKey();
  const signature = sodium.crypto_sign_detached(digest, privateKey);
  const signatureHex = sodium.to_hex(signature);
  
  return {
    'X-User-Pubkey': pubkeyHex,
    'X-Signature': signatureHex,
    'X-Timestamp': timestamp
  };
}

/**
 * Add authentication headers to a fetch options object
 * @param {string} method - HTTP method
 * @param {string} url - Full URL or path
 * @param {Object} options - Existing fetch options
 * @returns {Promise<Object>} Updated fetch options with auth headers
 */
export async function addAuthHeaders(method, url, options = {}) {
  // Parse URL to extract path and query
  let urlObj;
  try {
    urlObj = new URL(url);
  } catch (e) {
    // If URL parsing fails, assume it's a relative path
    const baseUrl = window.location.origin;
    urlObj = new URL(url, baseUrl);
  }
  
  const uri = urlObj.pathname;
  // Mongoose's hm->query does NOT include the "?" prefix (it's just the parameters)
  // urlObj.search includes "?" if present, so we need to strip it to match backend
  let query = urlObj.search;
  if (query && query.startsWith('?')) {
    query = query.substring(1); // Remove the "?" prefix to match mongoose's format
  }
  
  // Sign the request
  const authHeaders = await signRequest(method, uri, query);
  
  // Merge with existing headers (ensure headers is always an object)
  const existingHeaders = options.headers || {};
  const headers = {
    ...existingHeaders,
    ...authHeaders
  };
  
  return {
    ...options,
    headers
  };
}

