/**
 * Protobuf utility functions
 * Hex encoding/decoding utilities for protobuf data
 */

/**
 * Convert protobuf-serialized bytes to hex string
 * @param {Uint8Array} protobufBytes - Protobuf-serialized bytes
 * @returns {string} Hex-encoded string
 */
export function protobufToHex(protobufBytes) {
  // Simple hex encoding
  return Array.from(protobufBytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to Uint8Array
 * @param {string} hex - Hex-encoded string
 * @returns {Uint8Array} Binary data
 */
export function hexToProtobuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}




